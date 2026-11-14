// Licensed under GPL-2.0-or-later, matching Cargo.toml.
//! Explicit conservative DATA-read request budgets for donor admission.
use super::*;
use crate::packet::{FileSource, PacketSource};
use std::cell::RefCell;

/// Caller-owned aggregate allowance for explicit budgeted donor scans.
///
/// Charges are requested bytes, including exposed short/error/Interrupted attempts,
/// not measured returned bytes, or physical device traffic. There is no default limit.
#[derive(Debug)]
pub struct DonorReadBudget {
    limit: u64,
    charged: u64,
}
impl DonorReadBudget {
    /// Choose an aggregate requested-byte allowance. Reuse this ledger across calls.
    pub const fn new(total_limit_bytes: u64) -> Self {
        Self {
            limit: total_limit_bytes,
            charged: 0,
        }
    }
    /// Aggregate conservative requested-byte limit.
    pub const fn limit_bytes(&self) -> u64 {
        self.limit
    }
    /// Requested bytes charged before engine-issued DATA attempts, without refunds.
    pub const fn charged_bytes(&self) -> u64 {
        self.charged
    }
    /// Unspent requested-byte allowance, not a measurement of physical I/O remaining.
    pub const fn remaining_bytes(&self) -> u64 {
        self.limit - self.charged
    }
}
/// Allowance that refused a whole primitive read request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DonorReadScope {
    /// Shared allowance across calls.
    Aggregate,
    /// Optional allowance for this call.
    PerCall,
}
/// Failure of explicit budgeted donor admission, separate from incumbent errors.
#[derive(Debug)]
pub enum DonorReadError {
    /// Incumbent scan, source I/O, or cancellation error.
    Repair(RepairError),
    /// Whole requested attempt exceeds its conservative allowance; neither counter changes.
    Limit {
        /// Refusing allowance.
        scope: DonorReadScope,
        /// Configured limit.
        limit_bytes: u64,
        /// Already charged requested bytes in this scope.
        charged_bytes: u64,
        /// Next primitive request, not actual returned bytes.
        request_bytes: u64,
    },
    /// Arithmetic cannot represent a range or counter before any data read.
    CounterOverflow {
        /// Range or counter being advanced.
        counter: &'static str,
        /// Original value.
        value: u64,
        /// Original request length, retained without a lossy cast.
        request_bytes: usize,
    },
}
impl fmt::Display for DonorReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Repair(e) => e.fmt(f),
            Self::Limit {
                scope,
                limit_bytes,
                charged_bytes,
                request_bytes,
            } => write!(
                f,
                "{scope:?} donor requested-byte limit {limit_bytes}: {charged_bytes} charged, next request {request_bytes}"
            ),
            Self::CounterOverflow {
                counter,
                value,
                request_bytes,
            } => write!(
                f,
                "{counter} overflow adding {request_bytes} requested bytes to {value}"
            ),
        }
    }
}
impl std::error::Error for DonorReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Repair(e) => Some(e),
            _ => None,
        }
    }
}

trait Primitive {
    fn len(&self) -> u64;
    fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
}
struct DonorFile {
    source: FileSource,
    #[cfg(any(not(unix), test))]
    lock: Mutex<()>,
}
impl Primitive for DonorFile {
    fn len(&self) -> u64 {
        self.source.source_len()
    }
    #[cfg(unix)]
    fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        self.source.file().read_at(buf, offset)
    }
    #[cfg(not(unix))]
    fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.read_locked(offset, buf)
    }
}
impl DonorFile {
    fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            source: FileSource::open(path)?,
            #[cfg(any(not(unix), test))]
            lock: Mutex::new(()),
        })
    }
    // Compile and exercise this fallback body in native tests as well. That is
    // not a claim of qualification on a non-Unix target.
    #[cfg(any(not(unix), test))]
    fn read_locked(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::{Read, Seek, SeekFrom};
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = self.source.file();
        file.seek(SeekFrom::Start(offset))?;
        file.read(buf)
    }
}
struct State<'a> {
    budget: &'a mut DonorReadBudget,
    call_limit: Option<u64>,
    call_charged: u64,
    fault: Option<DonorReadError>,
    stopped: bool,
}
struct Metered<'a, P> {
    primitive: P,
    state: RefCell<State<'a>>,
    cancel: &'a AtomicBool,
}
impl<'a, P: Primitive> Metered<'a, P> {
    fn new(
        primitive: P,
        budget: &'a mut DonorReadBudget,
        call_limit: Option<u64>,
        cancel: &'a AtomicBool,
    ) -> Self {
        Self {
            primitive,
            state: RefCell::new(State {
                budget,
                call_limit,
                call_charged: 0,
                fault: None,
                stopped: false,
            }),
            cancel,
        }
    }
}
impl State<'_> {
    fn charge(&mut self, request: usize) -> Result<(), DonorReadError> {
        let amount = u64::try_from(request).map_err(|_| DonorReadError::CounterOverflow {
            counter: "aggregate donor counter",
            value: self.budget.charged,
            request_bytes: request,
        })?;
        let total =
            self.budget
                .charged
                .checked_add(amount)
                .ok_or(DonorReadError::CounterOverflow {
                    counter: "aggregate donor counter",
                    value: self.budget.charged,
                    request_bytes: request,
                })?;
        if total > self.budget.limit {
            return Err(DonorReadError::Limit {
                scope: DonorReadScope::Aggregate,
                limit_bytes: self.budget.limit,
                charged_bytes: self.budget.charged,
                request_bytes: amount,
            });
        }
        let call =
            self.call_charged
                .checked_add(amount)
                .ok_or(DonorReadError::CounterOverflow {
                    counter: "per-call donor counter",
                    value: self.call_charged,
                    request_bytes: request,
                })?;
        if let Some(limit) = self.call_limit
            && call > limit
        {
            return Err(DonorReadError::Limit {
                scope: DonorReadScope::PerCall,
                limit_bytes: limit,
                charged_bytes: self.call_charged,
                request_bytes: amount,
            });
        }
        self.budget.charged = total;
        self.call_charged = call;
        Ok(())
    }
}
impl<P: Primitive> Metered<'_, P> {
    fn fail(&self, error: DonorReadError) -> io::Error {
        let mut state = self.state.borrow_mut();
        if !state.stopped {
            state.fault = Some(error);
            state.stopped = true;
        }
        io::ErrorKind::Other.into()
    }
    fn io_fault(&self, error: io::Error) -> io::Error {
        self.fail(DonorReadError::Repair(io_ctx("reading budgeted donor")(
            error,
        )))
    }
    fn resolve<T>(&self, report: Result<T, RepairError>) -> Result<T, DonorReadError> {
        if let Some(error) = self.state.borrow_mut().fault.take() {
            return Err(error);
        }
        report.map_err(DonorReadError::Repair)
    }
}
impl<P: Primitive> PacketSource for Metered<'_, P> {
    fn source_len(&self) -> u64 {
        self.primitive.len()
    }
    fn read_at(&self, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
        if self.state.borrow().stopped {
            return Err(io::ErrorKind::Other.into());
        }
        if self.cancel.load(Ordering::Relaxed) {
            return Err(self.fail(DonorReadError::Repair(RepairError::Cancelled)));
        }
        let request = buf.len();
        let range = u64::try_from(request)
            .ok()
            .and_then(|n| offset.checked_add(n));
        let Some(end) = range else {
            return Err(self.fail(DonorReadError::CounterOverflow {
                counter: "donor read range",
                value: offset,
                request_bytes: request,
            }));
        };
        if end > self.source_len() {
            return Err(self.io_fault(io::ErrorKind::UnexpectedEof.into()));
        }
        while !buf.is_empty() {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(self.fail(DonorReadError::Repair(RepairError::Cancelled)));
            }
            let admitted = self.state.borrow_mut().charge(buf.len());
            if let Err(error) = admitted {
                return Err(self.fail(error));
            }
            match self.primitive.read_once(offset, buf) {
                Ok(0) => return Err(self.io_fault(io::ErrorKind::UnexpectedEof.into())),
                Ok(n) if n > buf.len() => {
                    return Err(self.io_fault(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "donor primitive returned more bytes than requested",
                    )));
                }
                Ok(n) => {
                    offset += n as u64;
                    buf = &mut buf[n..];
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(self.io_fault(e)),
            }
        }
        Ok(())
    }
}

enum Staged {
    Full(ScanReport),
    Ordered(super::donor::OrderedReport),
}
impl Par2Repairer {
    /// Scan an extra file with shared and optional per-call DATA-read allowances.
    ///
    /// Each engine-issued primitive call's entire requested length is charged before
    /// reading. Short/error/Interrupted attempts retain that charge; exposed retries
    /// need fresh allowance. These are conservative requested bytes, not measured
    /// returned bytes, device traffic, or kernel-internal retries. There is no default
    /// limit. Only this explicit admission call is metered, not verify, or repair.
    ///
    /// The existing prefetch size is retained: a budget smaller than its whole read
    /// request can refuse even when a shorter logical prefix would fit. Quota never
    /// becomes EOF or a smaller source length. Required-read errors/cancellation leave
    /// donor admission state unchanged; spent allowance and earlier calls remain.
    /// This adds no source-binding, memory, rollback, or blocking-I/O time guarantee.
    pub fn add_extra_file_with_read_budget(
        &mut self,
        path: &Path,
        policy: ExtraFileScanPolicy,
        budget: &mut DonorReadBudget,
        per_call_limit_bytes: Option<u64>,
        observer: &mut dyn RepairObserver,
    ) -> Result<usize, DonorReadError> {
        if !self.finalized {
            return Err(DonorReadError::Repair(RepairError::NotFinalized));
        }
        if self.scanned_extra.contains(path)
            || self
                .files
                .iter()
                .any(|f| f.target_path == path && f.status == FileStatus::Complete)
            || (self.missing_blocks() == 0
                && self.files.iter().all(|f| f.status == FileStatus::Complete))
        {
            return Ok(0);
        }
        if self.cancelled() {
            return Err(DonorReadError::Repair(RepairError::Cancelled));
        }
        observer.stage(Stage::ScanningExtra);
        observer.message(
            Level::Info,
            &format!("Scanning extra file {}", path.display()),
        );
        let file = DonorFile::open(path)
            .map_err(|e| DonorReadError::Repair(io_ctx("opening budgeted donor")(e)))?;
        let cancel = self.cancel.clone();
        let source = Metered::new(file, budget, per_call_limit_bytes, &cancel);
        self.admit_budgeted_source(path, policy, &source, observer)
    }

    fn admit_budgeted_source<P: Primitive>(
        &mut self,
        path: &Path,
        policy: ExtraFileScanPolicy,
        source: &Metered<'_, P>,
        observer: &mut dyn RepairObserver,
    ) -> Result<usize, DonorReadError> {
        let report = match policy {
            ExtraFileScanPolicy::Full => {
                let config = ScanConfig {
                    buffer_size: self.scan_resources(1).1,
                    ..ScanConfig::default()
                };
                let total = source.source_len().max(1);
                crate::scanner::scan_source(
                    source,
                    self.index.as_ref().unwrap(),
                    None,
                    &config,
                    Some(&self.cancel),
                    &mut |done| {
                        observer.progress(
                            ((u128::from(done.min(total)) * 1000) / u128::from(total)) as u32,
                            "Scanning budgeted donor",
                        );
                    },
                )
                .map_err(io_ctx("scanning budgeted donor"))
                .and_then(|report| {
                    if report.cancelled {
                        Err(RepairError::Cancelled)
                    } else {
                        Ok(Staged::Full(report))
                    }
                })
            }
            ExtraFileScanPolicy::OrderedPrefix => {
                let total = source.source_len().max(1);
                self.scan_ordered_source(source, self.disk_index.get(path).copied(), &mut |done| {
                    observer.progress(
                        ((u128::from(done.min(total)) * 1000) / u128::from(total)) as u32,
                        "Scanning budgeted ordered donor",
                    );
                })
                .map(Staged::Ordered)
            }
        };
        self.finish_budgeted_admission(path, source, report, observer)
    }

    fn finish_budgeted_admission<P: Primitive>(
        &mut self,
        path: &Path,
        source: &Metered<'_, P>,
        report: Result<Staged, RepairError>,
        observer: &mut dyn RepairObserver,
    ) -> Result<usize, DonorReadError> {
        // A hash helper may discard its temporary I/O error. The source's first
        // terminal fault is authoritative, including ahead of later cancellation.
        let report = source.resolve(report)?;
        observer.progress(1000, "Budgeted donor admission finished");
        if self.cancelled() {
            return Err(DonorReadError::Repair(RepairError::Cancelled));
        }
        let count = match report {
            Staged::Full(report) => {
                self.apply_scan(path, "budgeted donor", None, &report, observer)
            }
            Staged::Ordered(report) => self.apply_ordered(path, &report),
        };
        self.scanned_extra.insert(path.to_path_buf());
        Ok(count)
    }
}

#[cfg(test)]
mod tests;
