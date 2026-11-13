//! Pure sizing of physical sources and checked local loss ranges.
//!
//! Opaque keys do not identify filesystem objects or PAR2 file IDs.
//! A numeric plan does not establish stable bytes, global Reed-Solomon order,
//! verified parity availability, or a workflow completion state.

use crate::gf2::lcm;
use crate::packet::MAX_SLICE_SIZE;
use std::fmt;
use std::mem::size_of;
use std::ops::Range;

/// A caller-keyed physical source length. Empty files are allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSize {
    /// Opaque identifier, unique within a plan.
    pub key: u64,
    /// Physical bytes, excluding logical PAR2 padding.
    pub length: u64,
}

/// An explicit size or the minimum size satisfying aligned numeric constraints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SliceSizeRequest {
    /// Validate this size unchanged, without rounding.
    Exact(u64),
    /// Find the smallest multiple of `lcm(quantum_bytes, 4)` within the limits.
    SmallestAligned {
        /// Positive generic alignment quantum, in bytes.
        quantum_bytes: u64,
    },
}

/// Explicit positive per-call limits. Zero never means unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeometryLimits {
    /// Maximum number of files, including empty files.
    pub max_files: usize,
    /// Maximum aggregate source slices, at most 32768.
    pub max_source_slices: u32,
    /// Slice-size ceiling, from four through [`MAX_SLICE_SIZE`] bytes.
    /// The ceiling itself need not be divisible by four.
    pub max_slice_bytes: u64,
    /// Maximum input ranges per query, including empty ranges.
    pub max_ranges: usize,
    /// Maximum requested owned dynamic capacity bytes per call, including
    /// retained geometry during a loss query. Excludes allocator overhead,
    /// borrowed inputs, earlier query results, and concurrent calls.
    pub max_metadata_bytes: usize,
}

/// Bounded numeric admission errors, with no owned diagnostic strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeometryError {
    /// A budget is zero or a numeric ceiling exceeds the supported bounds.
    BadLimits,
    /// No physical source records were supplied.
    NoSources,
    /// Checked arithmetic could not represent a value.
    Overflow,
    /// The allocator refused a fallible reservation.
    AllocationFailed,
    /// No positive aligned size satisfies the supplied ceilings.
    NoAlignedSliceSize,
    /// An explicit slice size is zero, unaligned, or exceeds its ceiling.
    BadSliceSize {
        /// Requested slice bytes.
        requested: u64,
        /// Effective slice-byte ceiling.
        limit: u64,
    },
    /// The quantum is zero or its least common multiple with four overflows.
    BadAlignment(u64),
    /// File-count admission failed.
    TooManyFiles {
        /// Input record count.
        files: usize,
        /// Admitted file count.
        limit: usize,
    },
    /// An exact slice size exceeds the aggregate slice ceiling.
    TooManySourceSlices {
        /// Required source slices.
        slices: u64,
        /// Admitted source slices.
        limit: u32,
    },
    /// Two records share this opaque key.
    DuplicateKey(u64),
    /// Requested owned capacity exceeds the per-call metadata budget.
    MetadataLimit {
        /// Simultaneously live requested capacity bytes.
        requested: usize,
        /// Admitted requested capacity bytes.
        limit: usize,
    },
    /// Input range count exceeds its query budget.
    RangeLimit {
        /// Input range count, including empty ranges.
        ranges: usize,
        /// Admitted input range count.
        limit: usize,
    },
    /// No file has this opaque key, even for an empty query.
    UnknownKey(u64),
    /// A range is reversed or extends beyond the physical file.
    InvalidRange {
        /// Position of the invalid range in the borrowed input.
        index: usize,
    },
}

impl fmt::Display for GeometryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLimits => f.write_str("invalid geometry limits"),
            Self::NoSources => f.write_str("no source geometry records"),
            Self::Overflow => f.write_str("source geometry arithmetic overflow"),
            Self::AllocationFailed => f.write_str("source geometry allocation refused"),
            Self::NoAlignedSliceSize => f.write_str("no feasible aligned slice size"),
            Self::BadSliceSize { requested, limit } => {
                write!(f, "invalid slice size {requested} with ceiling {limit}")
            }
            Self::BadAlignment(quantum) => write!(f, "invalid alignment quantum {quantum}"),
            Self::TooManyFiles { files, limit } => write!(f, "{files} files exceed limit {limit}"),
            Self::TooManySourceSlices { slices, limit } => {
                write!(f, "{slices} source slices exceed limit {limit}")
            }
            Self::DuplicateKey(key) => write!(f, "duplicate source key {key}"),
            Self::MetadataLimit { requested, limit } => {
                write!(
                    f,
                    "requested metadata {requested} bytes exceed limit {limit}"
                )
            }
            Self::RangeLimit { ranges, limit } => write!(f, "{ranges} ranges exceed limit {limit}"),
            Self::UnknownKey(key) => write!(f, "unknown source key {key}"),
            Self::InvalidRange { index } => write!(f, "invalid physical range at index {index}"),
        }
    }
}

impl std::error::Error for GeometryError {}

/// Validated local geometry of one physical file, with no inferred global index.
#[derive(Debug, PartialEq, Eq)]
pub struct FileGeometry {
    key: u64,
    length: u64,
    source_slices: u32,
    padding_bytes: u64,
}

impl FileGeometry {
    /// Opaque caller identifier, not a PAR2 file ID.
    pub fn key(&self) -> u64 {
        self.key
    }
    /// Physical byte length, excluding logical padding.
    pub fn length(&self) -> u64 {
        self.length
    }
    /// Number of local source slices.
    pub fn source_slices(&self) -> u32 {
        self.source_slices
    }
    /// Logical zero padding at this file's tail; zero for an empty file.
    pub fn padding_bytes(&self) -> u64 {
        self.padding_bytes
    }
}

/// An owned numeric plan, sorted by opaque key rather than PAR2 file-ID order.
///
/// Owned plans deliberately do not implement `Clone`: creating capacity must
/// go through fallible admission. Keys and lengths establish no source binding.
#[derive(Debug)]
pub struct SourceGeometry {
    files: Vec<FileGeometry>,
    slice_bytes: u64,
    total_source_slices: u32,
    total_source_bytes: u64,
    total_padding_bytes: u64,
    requested_metadata_bytes: usize,
    vec_capacity_bytes: usize,
    limits: GeometryLimits,
}

impl SourceGeometry {
    /// Selected slice bytes.
    pub fn slice_bytes(&self) -> u64 {
        self.slice_bytes
    }
    /// Aggregate source-slice count with each physical tail counted separately.
    pub fn total_source_slices(&self) -> u32 {
        self.total_source_slices
    }
    /// Checked sum of physical source lengths.
    pub fn total_source_bytes(&self) -> u64 {
        self.total_source_bytes
    }
    /// Checked sum of logical padding across physical file tails.
    pub fn total_padding_bytes(&self) -> u64 {
        self.total_padding_bytes
    }
    /// Files in ascending opaque-key order. This is not Main-packet or RS order.
    pub fn files(&self) -> &[FileGeometry] {
        &self.files
    }
    /// Retained requested dynamic capacity: file count times record size.
    pub fn requested_metadata_bytes(&self) -> usize {
        self.requested_metadata_bytes
    }
    /// Actual advertised vector capacity times record size. This excludes
    /// allocator bookkeeping and is not a process-memory bound.
    pub fn vec_capacity_bytes(&self) -> usize {
        self.vec_capacity_bytes
    }

    /// Return the union of local slices intersecting strict physical ranges.
    ///
    /// Require `start <= end <= length`; empty valid ranges are no-ops. Unknown
    /// keys fail even for an empty query. Callers must check offset-plus-length
    /// arithmetic before constructing ranges. No clipping or I/O occurs.
    ///
    /// Query admission charges retained requested geometry bytes plus input
    /// range count times `size_of::<Range<u32>>()`, including empty ranges.
    /// The returned vector retains that requested capacity after merging; its
    /// actual capacity is observable with `Vec::capacity()`. Prior results and
    /// concurrent calls belong to the caller's aggregate resource accounting.
    /// Lookup is O(log F), validation O(M), and sorting O(M log M), with O(M)
    /// requested dynamic storage and no allocation for sorting or merging.
    pub fn lost_slice_ranges(
        &self,
        source_key: u64,
        ranges: &[Range<u64>],
    ) -> Result<Vec<Range<u32>>, GeometryError> {
        if ranges.len() > self.limits.max_ranges {
            return Err(GeometryError::RangeLimit {
                ranges: ranges.len(),
                limit: self.limits.max_ranges,
            });
        }
        let file = self
            .files
            .binary_search_by_key(&source_key, FileGeometry::key)
            .ok()
            .and_then(|index| self.files.get(index))
            .ok_or(GeometryError::UnknownKey(source_key))?;
        for (index, range) in ranges.iter().enumerate() {
            if range.start > range.end || range.end > file.length {
                return Err(GeometryError::InvalidRange { index });
            }
        }
        let range_bytes = ranges
            .len()
            .checked_mul(size_of::<Range<u32>>())
            .ok_or(GeometryError::Overflow)?;
        let requested = self
            .requested_metadata_bytes
            .checked_add(range_bytes)
            .ok_or(GeometryError::Overflow)?;
        check_metadata(requested, self.limits.max_metadata_bytes)?;
        let mut spans: Vec<Range<u32>> = Vec::new();
        spans
            .try_reserve_exact(ranges.len())
            .map_err(|_| GeometryError::AllocationFailed)?;
        for range in ranges.iter().filter(|range| range.start < range.end) {
            let first = u32::try_from(range.start / self.slice_bytes)
                .map_err(|_| GeometryError::Overflow)?;
            let end = u32::try_from((range.end - 1) / self.slice_bytes + 1)
                .map_err(|_| GeometryError::Overflow)?;
            spans.push(first..end);
        }
        spans.sort_unstable_by_key(|range| range.start);
        spans.dedup_by(|next, previous| {
            if next.start <= previous.end {
                previous.end = previous.end.max(next.end);
                true
            } else {
                false
            }
        });
        Ok(spans)
    }
}

fn check_metadata(requested: usize, limit: usize) -> Result<(), GeometryError> {
    if requested > limit {
        return Err(GeometryError::MetadataLimit { requested, limit });
    }
    Ok(())
}

fn source_slices(sources: &[SourceSize], slice: u64) -> Result<u64, GeometryError> {
    sources.iter().try_fold(0u64, |sum, source| {
        sum.checked_add(source.length.div_ceil(slice))
            .ok_or(GeometryError::Overflow)
    })
}

fn aligned_slice(
    sources: &[SourceSize],
    quantum: u64,
    limits: GeometryLimits,
) -> Result<u64, GeometryError> {
    let base = lcm(quantum, 4).ok_or(GeometryError::BadAlignment(quantum))?;
    let mut high = limits.max_slice_bytes / base;
    let mut low = 1;
    if high == 0 || source_slices(sources, high * base)? > u64::from(limits.max_source_slices) {
        return Err(GeometryError::NoAlignedSliceSize);
    }
    while low < high {
        let middle = low + (high - low) / 2;
        // Every multiplier is at most max_slice_bytes/base, so multiplication
        // is bounded by the supported slice-byte ceiling.
        if source_slices(sources, middle * base)? <= u64::from(limits.max_source_slices) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    Ok(low * base)
}

/// Plan physical source sizes without accessing files or inferring identities.
///
/// Exact sizes are unchanged. Aligned requests choose the minimum positive
/// multiple of `lcm(quantum, 4)` meeting the explicit slice-count ceiling. This
/// is not runtime, RSS or repair-cost optimization. Empty files contribute no
/// slices; a nonempty all-zero source list is valid geometry.
///
/// Construction requests one file vector of `sources.len() * size_of::<FileGeometry>()`
/// bytes, checked against the metadata budget before allocation. Borrowed input,
/// stack objects, allocator rounding and other calls are outside that promise.
/// Aligned scans allocate nothing; key sorting is allocation-free. Construction
/// is O(F log F) plus O(F log(max_slice_bytes / alignment)) for aligned selection.
///
/// Creation-scheme rules, first-exponent validation and recovery layouts remain
/// separate: compose the creator's checked APIs without treating numeric source
/// geometry as stable-byte, verified-parity, repairability, or publication proof.
pub fn checked_source_geometry(
    sources: &[SourceSize],
    request: SliceSizeRequest,
    limits: GeometryLimits,
) -> Result<SourceGeometry, GeometryError> {
    if limits.max_files == 0
        || limits.max_ranges == 0
        || limits.max_metadata_bytes == 0
        || !(1..=32768).contains(&limits.max_source_slices)
        || !(4..=MAX_SLICE_SIZE).contains(&limits.max_slice_bytes)
    {
        return Err(GeometryError::BadLimits);
    }
    if sources.is_empty() {
        return Err(GeometryError::NoSources);
    }
    if sources.len() > limits.max_files {
        return Err(GeometryError::TooManyFiles {
            files: sources.len(),
            limit: limits.max_files,
        });
    }
    let requested_metadata_bytes = sources
        .len()
        .checked_mul(size_of::<FileGeometry>())
        .ok_or(GeometryError::Overflow)?;
    check_metadata(requested_metadata_bytes, limits.max_metadata_bytes)?;
    let total_source_bytes = sources.iter().try_fold(0u64, |sum, source| {
        sum.checked_add(source.length)
            .ok_or(GeometryError::Overflow)
    })?;
    let slice_bytes = match request {
        SliceSizeRequest::Exact(size) => {
            if size == 0 || !size.is_multiple_of(4) || size > limits.max_slice_bytes {
                return Err(GeometryError::BadSliceSize {
                    requested: size,
                    limit: limits.max_slice_bytes,
                });
            }
            size
        }
        SliceSizeRequest::SmallestAligned { quantum_bytes } => {
            aligned_slice(sources, quantum_bytes, limits)?
        }
    };
    let total_slices = source_slices(sources, slice_bytes)?;
    if total_slices > u64::from(limits.max_source_slices) {
        return Err(GeometryError::TooManySourceSlices {
            slices: total_slices,
            limit: limits.max_source_slices,
        });
    }
    let mut files = Vec::new();
    files
        .try_reserve_exact(sources.len())
        .map_err(|_| GeometryError::AllocationFailed)?;
    let mut total_padding_bytes = 0u64;
    for source in sources {
        let padding_bytes = (slice_bytes - source.length % slice_bytes) % slice_bytes;
        total_padding_bytes = total_padding_bytes
            .checked_add(padding_bytes)
            .ok_or(GeometryError::Overflow)?;
        files.push(FileGeometry {
            key: source.key,
            length: source.length,
            source_slices: u32::try_from(source.length.div_ceil(slice_bytes))
                .map_err(|_| GeometryError::Overflow)?,
            padding_bytes,
        });
    }
    files.sort_unstable_by_key(FileGeometry::key);
    for pair in files.windows(2) {
        if let [previous, next] = pair
            && previous.key == next.key
        {
            return Err(GeometryError::DuplicateKey(next.key));
        }
    }
    let vec_capacity_bytes = files
        .capacity()
        .checked_mul(size_of::<FileGeometry>())
        .ok_or(GeometryError::Overflow)?;
    Ok(SourceGeometry {
        files,
        slice_bytes,
        total_source_slices: u32::try_from(total_slices).map_err(|_| GeometryError::Overflow)?,
        total_source_bytes,
        total_padding_bytes,
        requested_metadata_bytes,
        vec_capacity_bytes,
        limits,
    })
}
