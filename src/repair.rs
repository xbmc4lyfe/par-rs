//! Reed-Solomon repair of PAR2 input slices: batch in memory, surgical (a chosen subset of the
//! missing slices), and multi-file on disk.
//!
//! All repair is two-phase. With `C_i` the input constant of slice `i` and `R_e` the recovery
//! slice of exponent `e`, every recovery slice gives one equation
//!
//! ```text
//! S_e := R_e ⊕ ⨁_{i present} C_i^e · D_i  =  ⨁_{m missing} C_m^e · D_m
//! ```
//!
//! so `k` missing slices need `k` recovery slices; the `k × k` Vandermonde-like system is
//! inverted by Gaussian elimination over GF(2^16) and `D = A⁻¹ · S`. The syndromes are a single
//! cache-tiled SIMD pass over the present data, and the solve touches only `k` buffers.
//! [`repair_selected_slices`] computes just the requested rows of `A⁻¹ · S`, which is what a
//! streaming consumer wants when it only needs an archive header or tail slice.
//!
//! When exactly one slice is missing and exponent `0` is available, `C_i^0 = 1` and the repair
//! is a pure XOR (no field multiplication at all).

use crate::gf16::simd::{Kernel, MAX_MULTI};
use crate::gf16::{input_constant_logs, rs_coefficient};
use crate::reed_solomon::{Matrix, RsError, plan_recovery};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::PathBuf;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// L1-friendly tile for the multi-target kernel.
pub const TILE_BYTES: usize = 64 * 1024;

/// Why a repair failed.
#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    /// Fewer recovery slices than missing slices.
    #[error("{needed} slices are missing but only {available} recovery slices are available")]
    NotEnoughRecovery {
        /// Missing slices.
        needed: usize,
        /// Usable recovery slices.
        available: usize,
    },
    /// Every choice of recovery slices gave a singular matrix.
    #[error("recovery matrix is singular")]
    Singular,
    /// A slice buffer does not have the slice size.
    #[error("slice {index} has {got} bytes, expected {expected}")]
    SliceSizeMismatch {
        /// Slice (or recovery exponent) concerned.
        index: usize,
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// A slice index is out of range or duplicated.
    #[error("bad slice index {0}")]
    BadIndex(usize),
    /// More than 32768 input slices.
    #[error("too many input slices")]
    TooManyInputs,
    /// A requested slice is not missing.
    #[error("slice {0} is present, nothing to repair")]
    NotMissing(usize),
    /// Slice size of zero.
    #[error("slice size must be non-zero")]
    ZeroSliceSize,
    /// I/O error during disk repair.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
}

impl From<RsError> for RepairError {
    fn from(e: RsError) -> Self {
        match e {
            RsError::NotEnoughRecovery { needed, available } => RepairError::NotEnoughRecovery { needed, available },
            RsError::TooManyInputs => RepairError::TooManyInputs,
            RsError::Io(source) => RepairError::Io { context: "engine".into(), source },
            _ => RepairError::Singular,
        }
    }
}

/// Which recovery slices solve which missing slices.
#[derive(Clone, Debug)]
pub struct RepairPlan {
    /// Missing global slice indices, ascending; row `m` of the solution is `missing[m]`.
    pub missing: Vec<usize>,
    /// Recovery exponents used; column `j` of the inverse is syndrome `used_exponents[j]`.
    pub used_exponents: Vec<u32>,
    /// `A⁻¹`.
    pub inverse: Matrix,
    /// Logs of the input constants of all `total` slices.
    pub logs: Vec<u16>,
}

impl RepairPlan {
    /// Plan the repair of the slices absent from `present` (length `total`) with `exponents`.
    pub fn new(total: usize, present: &[bool], exponents: &[u32], kernel: &Kernel) -> Result<Self, RepairError> {
        if present.len() != total {
            return Err(RepairError::BadIndex(present.len()));
        }
        let logs = input_constant_logs(total).map_err(|_| RepairError::TooManyInputs)?;
        let plan = plan_recovery(&logs, present, exponents, kernel)?;
        Ok(Self { missing: plan.missing, used_exponents: plan.used_exponents, inverse: plan.inverse, logs })
    }

    /// Coefficient of present slice `i` in syndrome `j`.
    pub fn coefficient(&self, slice: usize, syndrome: usize) -> Option<u16> {
        let log = *self.logs.get(slice)?;
        let e = *self.used_exponents.get(syndrome)?;
        Some(rs_coefficient(log, e))
    }
}

/// `dsts[k] ^= coeffs[k] · src` for every destination, in [`TILE_BYTES`] tiles so the source
/// tile stays in L1 while all targets are updated.
pub fn fold_tiled(kernel: &Kernel, dsts: &mut [Vec<u8>], src: &[u8], coeffs: &[u16]) {
    let n = dsts.len().min(coeffs.len());
    let mut start = 0usize;
    while start < src.len() {
        let end = start.saturating_add(TILE_BYTES).min(src.len());
        let Some(src_tile) = src.get(start..end) else { break };
        let mut g = 0usize;
        while g < n {
            let g_end = g.saturating_add(MAX_MULTI).min(n);
            let Some(group) = dsts.get_mut(g..g_end) else { break };
            let mut tiles: Vec<&mut [u8]> = group.iter_mut().filter_map(|d| d.get_mut(start..end)).collect();
            if tiles.len() == g_end - g
                && let Some(c) = coeffs.get(g..g_end)
            {
                kernel.mul_acc_multi(&mut tiles, src_tile, c);
            }
            g = g_end;
        }
        start = end;
    }
}

/// XOR `src` into `dst` (equal lengths).
pub fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

fn check_len(index: usize, expected: usize, data: &[u8]) -> Result<(), RepairError> {
    if data.len() != expected { Err(RepairError::SliceSizeMismatch { index, expected, got: data.len() }) } else { Ok(()) }
}

/// Compute the syndromes `S_j = R_{e_j} ⊕ ⨁ C_i^{e_j} D_i` for a plan.
fn syndromes(plan: &RepairPlan, slice_size: usize, present: &[(usize, &[u8])], recovery: &[(u32, &[u8])], kernel: &Kernel) -> Result<Vec<Vec<u8>>, RepairError> {
    let k = plan.used_exponents.len();
    let mut syn: Vec<Vec<u8>> = vec![vec![0u8; slice_size]; k];
    for (j, &e) in plan.used_exponents.iter().enumerate() {
        let Some((_, r)) = recovery.iter().find(|(x, _)| *x == e) else { return Err(RepairError::Singular) };
        check_len(e as usize, slice_size, r)?;
        if let Some(s) = syn.get_mut(j) {
            xor_into(s, r);
        }
    }
    let fold_group = |group: &mut [Vec<u8>], first: usize| {
        for &(i, d) in present {
            let coeffs: Vec<u16> = (first..first.saturating_add(group.len())).map(|j| plan.coefficient(i, j).unwrap_or(0)).collect();
            fold_tiled(kernel, group, d, &coeffs);
        }
    };
    #[cfg(feature = "parallel")]
    {
        syn.par_chunks_mut(MAX_MULTI).enumerate().for_each(|(c, group)| fold_group(group, c.saturating_mul(MAX_MULTI)));
    }
    #[cfg(not(feature = "parallel"))]
    {
        for (c, group) in syn.chunks_mut(MAX_MULTI).enumerate() {
            fold_group(group, c.saturating_mul(MAX_MULTI));
        }
    }
    Ok(syn)
}

/// `D_m = ⨁_j inv[m][j] · S_j` for the requested rows.
fn solve_rows(plan: &RepairPlan, syn: &[Vec<u8>], slice_size: usize, rows: &[usize], kernel: &Kernel) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![vec![0u8; slice_size]; rows.len()];
    let solve_group = |group: &mut [Vec<u8>], first: usize| {
        for (j, s) in syn.iter().enumerate() {
            let coeffs: Vec<u16> = rows.iter().skip(first).take(group.len()).map(|&m| plan.inverse.get(m, j)).collect();
            fold_tiled(kernel, group, s, &coeffs);
        }
    };
    #[cfg(feature = "parallel")]
    {
        out.par_chunks_mut(MAX_MULTI).enumerate().for_each(|(c, group)| solve_group(group, c.saturating_mul(MAX_MULTI)));
    }
    #[cfg(not(feature = "parallel"))]
    {
        for (c, group) in out.chunks_mut(MAX_MULTI).enumerate() {
            solve_group(group, c.saturating_mul(MAX_MULTI));
        }
    }
    out
}

fn presence(total: usize, present: &[(usize, &[u8])], slice_size: usize) -> Result<Vec<bool>, RepairError> {
    if slice_size == 0 {
        return Err(RepairError::ZeroSliceSize);
    }
    let mut flags = vec![false; total];
    for &(i, d) in present {
        check_len(i, slice_size, d)?;
        match flags.get_mut(i) {
            Some(f) if !*f => *f = true,
            _ => return Err(RepairError::BadIndex(i)),
        }
    }
    Ok(flags)
}

/// Reconstruct every missing slice.
///
/// * `present`: `(global slice index, data)` of the available input slices, each exactly
///   `slice_size` bytes (zero pad the last slice of a file).
/// * `recovery`: `(exponent, data)` of the available recovery slices.
///
/// Returns `(global slice index, data)` for every slice in `0..total` that was not present.
pub fn repair_slices(slice_size: usize, total: usize, present: &[(usize, &[u8])], recovery: &[(u32, &[u8])], kernel: &Kernel) -> Result<Vec<(usize, Vec<u8>)>, RepairError> {
    let flags = presence(total, present, slice_size)?;
    let missing: Vec<usize> = flags.iter().enumerate().filter(|(_, p)| !**p).map(|(i, _)| i).collect();
    repair_rows(slice_size, total, &flags, &missing, present, recovery, kernel)
}

/// Reconstruct only `wanted` (a subset of the missing slices). All missing slices still count
/// towards the recovery slices required, but only the requested rows of `A⁻¹ · S` are formed.
pub fn repair_selected_slices(slice_size: usize, total: usize, present: &[(usize, &[u8])], recovery: &[(u32, &[u8])], wanted: &[usize], kernel: &Kernel) -> Result<Vec<(usize, Vec<u8>)>, RepairError> {
    let flags = presence(total, present, slice_size)?;
    let mut rows = wanted.to_vec();
    rows.sort_unstable();
    rows.dedup();
    for &w in &rows {
        match flags.get(w) {
            None => return Err(RepairError::BadIndex(w)),
            Some(true) => return Err(RepairError::NotMissing(w)),
            Some(false) => {}
        }
    }
    repair_rows(slice_size, total, &flags, &rows, present, recovery, kernel)
}

fn repair_rows(slice_size: usize, total: usize, flags: &[bool], wanted: &[usize], present: &[(usize, &[u8])], recovery: &[(u32, &[u8])], kernel: &Kernel) -> Result<Vec<(usize, Vec<u8>)>, RepairError> {
    let missing_count = flags.iter().filter(|p| !**p).count();
    if missing_count == 0 || wanted.is_empty() {
        return Ok(Vec::new());
    }
    // Exponent-0 fast path: one missing slice and R_0 on hand.
    if missing_count == 1
        && let Some((_, r0)) = recovery.iter().find(|(e, _)| *e == 0)
        && let Some(&m) = wanted.first()
    {
        check_len(0, slice_size, r0)?;
        let mut out = r0.to_vec();
        for &(_, d) in present {
            xor_into(&mut out, d);
        }
        return Ok(vec![(m, out)]);
    }
    let exps: Vec<u32> = recovery.iter().map(|(e, _)| *e).collect();
    let plan = RepairPlan::new(total, flags, &exps, kernel)?;
    let syn = syndromes(&plan, slice_size, present, recovery, kernel)?;
    let rows: Vec<usize> = wanted.iter().filter_map(|w| plan.missing.iter().position(|m| m == w)).collect();
    let solved = solve_rows(&plan, &syn, slice_size, &rows, kernel);
    Ok(rows.iter().zip(solved).filter_map(|(&r, d)| plan.missing.get(r).map(|&g| (g, d))).collect())
}

// ---------------------------------------------------------------------------------------------
// Disk repair
// ---------------------------------------------------------------------------------------------

/// A target file of a disk repair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskFile {
    /// Path to write (created or extended as needed).
    pub path: PathBuf,
    /// Declared size.
    pub size: u64,
    /// Global index of its first slice.
    pub first_slice: usize,
    /// Number of slices.
    pub slice_count: usize,
}

/// Where a present slice lives on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskLocation {
    /// Path of the file holding the slice (the target itself, a backup, a misnamed copy ...).
    pub path: PathBuf,
    /// Byte offset of the slice data.
    pub offset: u64,
}

/// A recovery slice on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskRecovery {
    /// Par2 file.
    pub path: PathBuf,
    /// Offset of the recovery data (after the packet header and exponent).
    pub offset: u64,
    /// Exponent.
    pub exponent: u32,
}

/// Everything a disk repair needs.
#[derive(Clone, Debug)]
pub struct DiskRepairPlan {
    /// Slice size.
    pub slice_size: u64,
    /// Target files, covering `0..total` slices contiguously in order.
    pub files: Vec<DiskFile>,
    /// Per global slice: where its verified data is, or `None` when missing.
    pub present: Vec<Option<DiskLocation>>,
    /// Available recovery slices.
    pub recovery: Vec<DiskRecovery>,
}

/// Result of a disk repair.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiskRepairReport {
    /// Global slices written.
    pub repaired: Vec<usize>,
    /// Bytes read from present slices and recovery data.
    pub bytes_read: u64,
    /// Bytes written.
    pub bytes_written: u64,
}

fn io_err(context: impl Into<String>) -> impl FnOnce(io::Error) -> RepairError {
    move |source| RepairError::Io { context: context.into(), source }
}

/// Read-only access to a source file.
enum Source {
    #[cfg(feature = "mmap")]
    Map(memmap2::Mmap),
    Fd(File),
}

impl Source {
    fn open(path: &PathBuf) -> Result<Self, RepairError> {
        let f = File::open(path).map_err(io_err(format!("opening {}", path.display())))?;
        #[cfg(feature = "mmap")]
        {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            if len > 0
                // SAFETY: the mapping is private and read-only; the files are inputs the caller
                // asked us to read, and a concurrent writer would at worst corrupt the data we
                // verify afterwards, never memory safety here.
                && let Ok(m) = unsafe { memmap2::Mmap::map(&f) }
            {
                return Ok(Source::Map(m));
            }
        }
        Ok(Source::Fd(f))
    }

    /// Read `[offset, offset + buf.len())`, zero filling past the end of the file.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RepairError> {
        match self {
            #[cfg(feature = "mmap")]
            Source::Map(m) => {
                let start = usize::try_from(offset).unwrap_or(usize::MAX).min(m.len());
                let end = start.saturating_add(buf.len()).min(m.len());
                let n = end - start;
                if let (Some(dst), Some(src)) = (buf.get_mut(..n), m.get(start..end)) {
                    dst.copy_from_slice(src);
                }
                if let Some(tail) = buf.get_mut(n..) {
                    tail.fill(0);
                }
                Ok(n)
            }
            Source::Fd(f) => {
                let mut done = 0usize;
                while done < buf.len() {
                    let Some(dst) = buf.get_mut(done..) else { break };
                    let n = read_at(f, offset.saturating_add(done as u64), dst).map_err(io_err("reading"))?;
                    if n == 0 {
                        break;
                    }
                    done = done.saturating_add(n);
                }
                if let Some(tail) = buf.get_mut(done..) {
                    tail.fill(0);
                }
                Ok(done)
            }
        }
    }
}

#[cfg(unix)]
fn read_at(f: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    f.read_at(buf, offset)
}

#[cfg(windows)]
fn read_at(f: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    f.seek_read(buf, offset)
}

#[cfg(unix)]
fn write_all_at(f: &File, offset: u64, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.write_all_at(data, offset)
}

#[cfg(windows)]
fn write_all_at(f: &File, offset: u64, data: &[u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0usize;
    while done < data.len() {
        let n = f.seek_write(data.get(done..).unwrap_or(&[]), offset.saturating_add(done as u64))?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
        }
        done = done.saturating_add(n);
    }
    Ok(())
}

/// Repair the missing slices of several files on disk: syndromes are accumulated slice by slice
/// from the present data (memory: `k` slice buffers), solved, and the results written into the
/// target files at their natural offsets (files are created / sized as needed).
pub fn repair_on_disk(plan: &DiskRepairPlan, kernel: &Kernel) -> Result<DiskRepairReport, RepairError> {
    let slice_size = usize::try_from(plan.slice_size).map_err(|_| RepairError::ZeroSliceSize)?;
    if slice_size == 0 {
        return Err(RepairError::ZeroSliceSize);
    }
    let total = plan.present.len();
    let flags: Vec<bool> = plan.present.iter().map(Option::is_some).collect();
    let missing: Vec<usize> = flags.iter().enumerate().filter(|(_, p)| !**p).map(|(i, _)| i).collect();
    let mut report = DiskRepairReport::default();
    if missing.is_empty() {
        return Ok(report);
    }
    let exps: Vec<u32> = plan.recovery.iter().map(|r| r.exponent).collect();
    let rp = RepairPlan::new(total, &flags, &exps, kernel)?;
    let k = rp.used_exponents.len();
    let mut sources: HashMap<PathBuf, Source> = HashMap::new();
    let source_for = |path: &PathBuf, sources: &mut HashMap<PathBuf, Source>| -> Result<(), RepairError> {
        if !sources.contains_key(path) {
            sources.insert(path.clone(), Source::open(path)?);
        }
        Ok(())
    };
    // Syndromes start as the recovery slices.
    let mut syn: Vec<Vec<u8>> = vec![vec![0u8; slice_size]; k];
    let mut buf = vec![0u8; slice_size];
    for (j, &e) in rp.used_exponents.iter().enumerate() {
        let Some(r) = plan.recovery.iter().find(|r| r.exponent == e) else { return Err(RepairError::Singular) };
        source_for(&r.path, &mut sources)?;
        let n = sources.get(&r.path).ok_or(RepairError::Singular)?.read_at(r.offset, &mut buf)?;
        report.bytes_read = report.bytes_read.saturating_add(n as u64);
        if let Some(s) = syn.get_mut(j) {
            xor_into(s, &buf);
        }
    }
    // Fold every present slice.
    for (i, loc) in plan.present.iter().enumerate() {
        let Some(loc) = loc else { continue };
        source_for(&loc.path, &mut sources)?;
        let n = sources.get(&loc.path).ok_or(RepairError::Singular)?.read_at(loc.offset, &mut buf)?;
        report.bytes_read = report.bytes_read.saturating_add(n as u64);
        let coeffs: Vec<u16> = (0..k).map(|j| rp.coefficient(i, j).unwrap_or(0)).collect();
        fold_tiled(kernel, &mut syn, &buf, &coeffs);
    }
    drop(sources);
    let rows: Vec<usize> = (0..rp.missing.len()).collect();
    let solved = solve_rows(&rp, &syn, slice_size, &rows, kernel);
    // Write.
    let mut targets: HashMap<usize, File> = HashMap::new();
    for (m, data) in rp.missing.iter().zip(solved) {
        let Some(fi) = plan.files.iter().position(|f| *m >= f.first_slice && *m < f.first_slice.saturating_add(f.slice_count)) else {
            return Err(RepairError::BadIndex(*m));
        };
        let Some(file) = plan.files.get(fi) else { return Err(RepairError::BadIndex(*m)) };
        if let std::collections::hash_map::Entry::Vacant(v) = targets.entry(fi) {
            let f = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&file.path).map_err(io_err(format!("opening {}", file.path.display())))?;
            if f.metadata().map(|md| md.len()).unwrap_or(0) < file.size {
                f.set_len(file.size).map_err(io_err(format!("sizing {}", file.path.display())))?;
            }
            v.insert(f);
        }
        let Some(f) = targets.get(&fi) else { continue };
        let slice_in_file = (*m - file.first_slice) as u64;
        let offset = slice_in_file.saturating_mul(plan.slice_size);
        let len = usize::try_from(file.size.saturating_sub(offset).min(plan.slice_size)).unwrap_or(0);
        write_all_at(f, offset, data.get(..len).unwrap_or(&[])).map_err(io_err(format!("writing {}", file.path.display())))?;
        report.bytes_written = report.bytes_written.saturating_add(len as u64);
        report.repaired.push(*m);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::encode_reference;

    fn data(n: usize, seed: u32) -> Vec<u8> {
        (0..n as u32).map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed) >> 13) as u8).collect()
    }

    type Set = (Vec<Vec<u8>>, Vec<(u32, Vec<u8>)>);

    fn set(n: usize, ss: usize, exps: &[u32]) -> Set {
        let inputs: Vec<Vec<u8>> = (0..n).map(|i| data(ss, i as u32 + 1)).collect();
        let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
        let rec = encode_reference(ss, &refs, exps);
        (inputs, exps.iter().copied().zip(rec).collect())
    }

    #[test]
    fn batch_surgical_and_xor_fast_path() {
        let k = Kernel::detect();
        let ss = 2000;
        let (inputs, rec) = set(12, ss, &[0, 1, 2, 3, 4]);
        let recovery: Vec<(u32, &[u8])> = rec.iter().map(|(e, d)| (*e, d.as_slice())).collect();
        let missing = [2usize, 5, 11];
        let present: Vec<(usize, &[u8])> = inputs.iter().enumerate().filter(|(i, _)| !missing.contains(i)).map(|(i, d)| (i, d.as_slice())).collect();
        let out = repair_slices(ss, 12, &present, &recovery, &k).unwrap();
        assert_eq!(out.len(), 3);
        for (g, d) in &out {
            assert_eq!(d, &inputs[*g], "slice {g}");
        }
        // Surgical: only slice 11.
        let out = repair_selected_slices(ss, 12, &present, &recovery, &[11, 11], &k).unwrap();
        assert_eq!(out, vec![(11, inputs[11].clone())]);
        assert!(matches!(repair_selected_slices(ss, 12, &present, &recovery, &[1], &k), Err(RepairError::NotMissing(1))));
        assert!(matches!(repair_selected_slices(ss, 12, &present, &recovery, &[99], &k), Err(RepairError::BadIndex(99))));
        // Not enough recovery.
        assert!(matches!(repair_slices(ss, 12, &present, &recovery[..2], &k), Err(RepairError::NotEnoughRecovery { needed: 3, available: 2 })));
        // XOR fast path: one missing, exponent 0 only.
        let present1: Vec<(usize, &[u8])> = inputs.iter().enumerate().filter(|(i, _)| *i != 7).map(|(i, d)| (i, d.as_slice())).collect();
        let out = repair_slices(ss, 12, &present1, &recovery[..1], &k).unwrap();
        assert_eq!(out, vec![(7, inputs[7].clone())]);
        // ... and without exponent 0 it goes through the field.
        let out = repair_slices(ss, 12, &present1, &recovery[3..4], &k).unwrap();
        assert_eq!(out, vec![(7, inputs[7].clone())]);
        // Nothing missing.
        let all: Vec<(usize, &[u8])> = inputs.iter().enumerate().map(|(i, d)| (i, d.as_slice())).collect();
        assert!(repair_slices(ss, 12, &all, &recovery, &k).unwrap().is_empty());
        // Errors.
        assert!(matches!(repair_slices(ss, 12, &[(0, &inputs[0][..10])], &recovery, &k), Err(RepairError::SliceSizeMismatch { .. })));
        assert!(matches!(repair_slices(ss, 12, &[(0, &inputs[0]), (0, &inputs[1])], &recovery, &k), Err(RepairError::BadIndex(0))));
        assert!(matches!(repair_slices(0, 12, &[], &recovery, &k), Err(RepairError::ZeroSliceSize)));
        let short = [(1u32, &rec[1].1[..5])];
        assert!(matches!(repair_slices(ss, 12, &present1, &short, &k), Err(RepairError::SliceSizeMismatch { .. })));
        assert_eq!(RepairError::Singular.to_string(), "recovery matrix is singular");
        assert!(matches!(RepairError::from(RsError::TooManyInputs), RepairError::TooManyInputs));
    }

    #[test]
    fn many_targets_tiled() {
        let k = Kernel::detect();
        let ss = 70_000; // crosses tile boundaries
        let (inputs, rec) = set(20, ss, &(0..20u32).collect::<Vec<_>>());
        let recovery: Vec<(u32, &[u8])> = rec.iter().map(|(e, d)| (*e, d.as_slice())).collect();
        let present: Vec<(usize, &[u8])> = inputs.iter().enumerate().filter(|(i, _)| i % 2 == 0).map(|(i, d)| (i, d.as_slice())).collect();
        let out = repair_slices(ss, 20, &present, &recovery, &k).unwrap();
        assert_eq!(out.len(), 10);
        for (g, d) in &out {
            assert_eq!(d, &inputs[*g]);
        }
    }

    #[test]
    fn disk_repair_round_trip() {
        let k = Kernel::detect();
        let ss = 1000usize;
        let dir = std::env::temp_dir().join(format!("par-rs-repair-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Two files: a = 2500 bytes (3 slices), b = 2000 bytes (2 slices).
        let a = data(2500, 1);
        let b = data(2000, 2);
        let mut slices: Vec<Vec<u8>> = Vec::new();
        for f in [&a, &b] {
            for c in f.chunks(ss) {
                let mut p = c.to_vec();
                p.resize(ss, 0);
                slices.push(p);
            }
        }
        let refs: Vec<&[u8]> = slices.iter().map(|s| s.as_slice()).collect();
        let rec = encode_reference(ss, &refs, &[0, 1, 2]);
        let mut vol = Vec::new();
        let mut rec_offsets = Vec::new();
        for (e, r) in rec.iter().enumerate() {
            vol.extend_from_slice(&[0xAA; 68]); // fake header
            rec_offsets.push((e as u32, vol.len() as u64));
            vol.extend_from_slice(r);
        }
        let vol_path = dir.join("set.vol.par2");
        std::fs::write(&vol_path, &vol).unwrap();
        // Damage: a slice 1 corrupt (kept on disk as a.bak), b missing entirely.
        let a_path = dir.join("a.bin");
        let mut dmg = a.clone();
        dmg[1500] ^= 1;
        std::fs::write(&a_path, &dmg).unwrap();
        let b_path = dir.join("b.bin");
        let plan = DiskRepairPlan {
            slice_size: ss as u64,
            files: vec![
                DiskFile { path: a_path.clone(), size: 2500, first_slice: 0, slice_count: 3 },
                DiskFile { path: b_path.clone(), size: 2000, first_slice: 3, slice_count: 2 },
            ],
            present: vec![
                Some(DiskLocation { path: a_path.clone(), offset: 0 }),
                None,
                Some(DiskLocation { path: a_path.clone(), offset: 2000 }),
                None,
                None,
            ],
            recovery: rec_offsets.iter().map(|&(e, o)| DiskRecovery { path: vol_path.clone(), offset: o, exponent: e }).collect(),
        };
        let report = repair_on_disk(&plan, &k).unwrap();
        assert_eq!(report.repaired, vec![1, 3, 4]);
        assert_eq!(report.bytes_written, 1000 + 2000);
        assert_eq!(std::fs::read(&a_path).unwrap(), a);
        assert_eq!(std::fs::read(&b_path).unwrap(), b);
        // Nothing missing: no-op.
        let mut all = plan.clone();
        all.present[1] = Some(DiskLocation { path: a_path.clone(), offset: 1000 });
        all.present[3] = Some(DiskLocation { path: b_path.clone(), offset: 0 });
        all.present[4] = Some(DiskLocation { path: b_path.clone(), offset: 1000 });
        assert!(repair_on_disk(&all, &k).unwrap().repaired.is_empty());
        // Missing source file surfaces as Io.
        let mut bad = plan.clone();
        bad.present[0] = Some(DiskLocation { path: dir.join("nope"), offset: 0 });
        assert!(matches!(repair_on_disk(&bad, &k), Err(RepairError::Io { .. })));
        let mut zero = plan.clone();
        zero.slice_size = 0;
        assert!(matches!(repair_on_disk(&zero, &k), Err(RepairError::ZeroSliceSize)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
