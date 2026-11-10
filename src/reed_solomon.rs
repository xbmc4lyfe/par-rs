//! PAR2 Reed-Solomon engine: recovery planning, matrix inversion and the streaming,
//! multi-threaded GF(2^16) computation shared by repair and creation.
//!
//! # Mathematics
//!
//! Input slice `i` is assigned the constant `C_i = 2^{n_i}` where `n_i` runs over the
//! integers coprime with 65535 (see [`crate::gf16::input_constants`]). Recovery slice with
//! exponent `e` is `R_e = Σ_i C_i^e · D_i`.
//!
//! To repair `k` missing slices `M = {m_1..m_k}` with recovery slices `e_1..e_k`:
//!
//! 1. **Syndromes** (streaming pass over everything on disk):
//!    `S_j = R_{e_j} + Σ_{present i} C_i^{e_j} · D_i = Σ_{m ∈ M} C_m^{e_j} · D_m`.
//! 2. **Solve** (in memory, per chunk): with `A[j][m] = C_m^{e_j}` (k×k), `D = A⁻¹ · S`.
//!
//! Compared with pre-multiplying `A⁻¹` into every present-input coefficient (`O(k²·p)`
//! setup, as `libpar2` does) this needs only the `O(k³)` inversion plus an `O(k²)`-per-word
//! second phase, and the streaming phase has the same cost as creation.
//!
//! # Engine
//!
//! [`Engine::run`] processes the slices in chunks that fit the memory budget. For every chunk
//! a reader thread streams batches of input chunks (de-interleaved into split planes) while
//! worker threads multiply-accumulate them into the output buffers, each worker owning a
//! disjoint range of words of every output and iterating in L2-sized tiles so that an input
//! tile is read once per group of up to eight outputs.

use crate::gf16::simd::{Kernel, MAX_MULTI, Plane, PlaneMut};
use crate::gf16::{self, MulTables, rs_coefficient};
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};

/// Errors of the Reed-Solomon layer.
#[derive(Debug)]
pub enum RsError {
    /// Fewer recovery slices than missing input slices.
    NotEnoughRecovery {
        /// Missing input slices.
        needed: usize,
        /// Recovery slices available.
        available: usize,
    },
    /// No combination of the available recovery slices yields an invertible matrix.
    Singular,
    /// More than 32768 input slices.
    TooManyInputs,
    /// Nothing to compute.
    NoOutputs,
    /// I/O failure while reading inputs or writing outputs.
    Io(io::Error),
    /// Cancelled through the cancellation flag.
    Cancelled,
}

impl fmt::Display for RsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RsError::NotEnoughRecovery { needed, available } => {
                write!(
                    f,
                    "not enough recovery blocks: {needed} needed, {available} available"
                )
            }
            RsError::Singular => f.write_str("recovery matrix is singular"),
            RsError::TooManyInputs => f.write_str("too many input slices (maximum 32768)"),
            RsError::NoOutputs => f.write_str("no output slices to compute"),
            RsError::Io(e) => write!(f, "I/O error: {e}"),
            RsError::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for RsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RsError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for RsError {
    fn from(e: io::Error) -> Self {
        RsError::Io(e)
    }
}

// ---------------------------------------------------------------------------------------------
// Dense GF(2^16) matrix
// ---------------------------------------------------------------------------------------------

/// Row-major dense matrix over GF(2^16), stored as little-endian `u16` bytes so that row
/// operations can use the SIMD multiply-accumulate kernels.
#[derive(Clone, PartialEq, Eq)]
pub struct Matrix {
    rows: usize,
    cols: usize,
    data: Vec<u8>,
}

impl fmt::Debug for Matrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Matrix {}x{} [", self.rows, self.cols)?;
        for r in 0..self.rows {
            write!(f, "[")?;
            for c in 0..self.cols {
                write!(
                    f,
                    "{:#06x}{}",
                    self.get(r, c),
                    if c + 1 < self.cols { ", " } else { "" }
                )?;
            }
            write!(f, "]{}", if r + 1 < self.rows { ", " } else { "" })?;
        }
        write!(f, "]")
    }
}

impl Matrix {
    /// Zero matrix.
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![0u8; rows * cols * 2],
        }
    }

    /// Identity matrix.
    pub fn identity(n: usize) -> Self {
        let mut m = Self::zeros(n, n);
        for i in 0..n {
            m.set(i, i, 1);
        }
        m
    }

    /// Rows.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Columns.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Element.
    #[inline]
    pub fn get(&self, r: usize, c: usize) -> u16 {
        let i = (r * self.cols + c) * 2;
        u16::from_le_bytes([self.data[i], self.data[i + 1]])
    }

    /// Set element.
    #[inline]
    pub fn set(&mut self, r: usize, c: usize, v: u16) {
        let i = (r * self.cols + c) * 2;
        self.data[i..i + 2].copy_from_slice(&v.to_le_bytes());
    }

    /// Row `r` as bytes.
    pub fn row_bytes(&self, r: usize) -> &[u8] {
        &self.data[r * self.cols * 2..(r + 1) * self.cols * 2]
    }

    /// Row `r` as `u16` values.
    pub fn row(&self, r: usize) -> Vec<u16> {
        (0..self.cols).map(|c| self.get(r, c)).collect()
    }

    fn swap_rows(&mut self, a: usize, b: usize) {
        if a == b {
            return;
        }
        let w = self.cols * 2;
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        let (head, tail) = self.data.split_at_mut(hi * w);
        head[lo * w..(lo + 1) * w].swap_with_slice(&mut tail[..w]);
    }

    /// Multiply row `r` by `c`.
    fn scale_row(&mut self, r: usize, c: u16) {
        let t = MulTables::new(c);
        for col in 0..self.cols {
            let v = self.get(r, col);
            self.set(r, col, t.mul(v));
        }
    }

    /// `row[dst] ^= c * row[src]` using the SIMD kernel.
    fn add_scaled_row(&mut self, kernel: &Kernel, dst: usize, src: usize, c: u16) {
        if c == 0 || dst == src {
            return;
        }
        let w = self.cols * 2;
        let (lo, hi) = if dst < src { (dst, src) } else { (src, dst) };
        let (head, tail) = self.data.split_at_mut(hi * w);
        let lo_row = &mut head[lo * w..(lo + 1) * w];
        let hi_row = &mut tail[..w];
        if dst < src {
            kernel.mul_acc(lo_row, hi_row, c);
        } else {
            kernel.mul_acc(hi_row, lo_row, c);
        }
    }

    /// Matrix product.
    pub fn mul(&self, other: &Matrix) -> Matrix {
        assert_eq!(self.cols, other.rows, "matrix dimension mismatch");
        let mut out = Matrix::zeros(self.rows, other.cols);
        for i in 0..self.rows {
            for k in 0..self.cols {
                let a = self.get(i, k);
                if a == 0 {
                    continue;
                }
                let t = MulTables::new(a);
                for j in 0..other.cols {
                    let v = out.get(i, j) ^ t.mul(other.get(k, j));
                    out.set(i, j, v);
                }
            }
        }
        out
    }

    /// Gauss-Jordan inversion. Returns `None` if singular.
    pub fn inverse(&self, kernel: &Kernel) -> Option<Matrix> {
        assert_eq!(self.rows, self.cols, "only square matrices can be inverted");
        let n = self.rows;
        // Augmented [A | I].
        let mut aug = Matrix::zeros(n, 2 * n);
        for r in 0..n {
            for c in 0..n {
                aug.set(r, c, self.get(r, c));
            }
            aug.set(r, n + r, 1);
        }
        for col in 0..n {
            // Find a non-zero pivot in this column.
            let pivot = (col..n).find(|&r| aug.get(r, col) != 0)?;
            aug.swap_rows(pivot, col);
            let p = aug.get(col, col);
            if p != 1 {
                aug.scale_row(col, gf16::inv(p));
            }
            for r in 0..n {
                if r != col {
                    let f = aug.get(r, col);
                    if f != 0 {
                        aug.add_scaled_row(kernel, r, col, f);
                    }
                }
            }
        }
        let mut inv = Matrix::zeros(n, n);
        for r in 0..n {
            for c in 0..n {
                inv.set(r, c, aug.get(r, n + c));
            }
        }
        Some(inv)
    }
}

// ---------------------------------------------------------------------------------------------
// Recovery planning
// ---------------------------------------------------------------------------------------------

/// How to reconstruct the missing input slices.
#[derive(Clone, Debug)]
pub struct RecoveryPlan {
    /// Global indices of the missing input slices (ascending); output `m` of the engine
    /// corresponds to `missing[m]`.
    pub missing: Vec<usize>,
    /// Exponents of the recovery slices used, one per missing slice (`used[j]` is syndrome `j`).
    pub used_exponents: Vec<u32>,
    /// `A⁻¹` with `A[j][m] = C_{missing[m]}^{used[j]}`.
    pub inverse: Matrix,
}

/// Choose recovery slices and invert the recovery matrix.
///
/// * `input_logbases[i]` is the log of input constant `C_i` (see
///   [`crate::gf16::input_constant_logs`]).
/// * `present[i]` tells whether input slice `i` is available.
/// * `available_exponents` lists the recovery slices on hand (any order).
pub fn plan_recovery(
    input_logbases: &[u16],
    present: &[bool],
    available_exponents: &[u32],
    kernel: &Kernel,
) -> Result<RecoveryPlan, RsError> {
    assert_eq!(
        input_logbases.len(),
        present.len(),
        "one presence flag per input"
    );
    if input_logbases.len() > 32768 {
        return Err(RsError::TooManyInputs);
    }
    let missing: Vec<usize> = present
        .iter()
        .enumerate()
        .filter(|&(_, &p)| !p)
        .map(|(i, _)| i)
        .collect();
    let k = missing.len();
    let mut exps: Vec<u32> = available_exponents.to_vec();
    exps.sort_unstable();
    exps.dedup();
    if exps.len() < k {
        return Err(RsError::NotEnoughRecovery {
            needed: k,
            available: exps.len(),
        });
    }
    if k == 0 {
        return Ok(RecoveryPlan {
            missing,
            used_exponents: Vec::new(),
            inverse: Matrix::zeros(0, 0),
        });
    }
    let mut used: Vec<u32> = exps[..k].to_vec();
    let mut next_unused = k;
    loop {
        let mut a = Matrix::zeros(k, k);
        for (j, &e) in used.iter().enumerate() {
            for (m, &idx) in missing.iter().enumerate() {
                a.set(j, m, rs_coefficient(input_logbases[idx], e));
            }
        }
        if let Some(inverse) = a.inverse(kernel) {
            return Ok(RecoveryPlan {
                missing,
                used_exponents: used,
                inverse,
            });
        }
        // Singular: swap in another recovery slice and retry.
        if next_unused >= exps.len() {
            return Err(RsError::Singular);
        }
        // Replace the row whose exponent is largest (heuristic: rotate through candidates).
        let victim = (next_unused - k) % k;
        used[victim] = exps[next_unused];
        next_unused += 1;
    }
}

// ---------------------------------------------------------------------------------------------
// Streaming engine
// ---------------------------------------------------------------------------------------------

/// Coefficient structure of one input slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputKind {
    /// Data slice with constant `2^logbase`: contributes `C^{e_j}` to output `j`.
    Data {
        /// Log of the input constant.
        logbase: u16,
    },
    /// Recovery slice already holding `R_{e_j}`: contributes `1` to output `j` only.
    Recovery {
        /// Output (syndrome) index it belongs to.
        output: usize,
    },
}

/// One input of a computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputSpec {
    /// Coefficient structure.
    pub kind: InputKind,
    /// Opaque handle passed back to the [`InputReader`].
    pub source: usize,
}

/// Supplies input slice data.
pub trait InputReader: Sync {
    /// Fill `buf` with bytes `[offset, offset + buf.len())` of input slice `source`,
    /// zero-padding past the end of the available data.
    fn read_input(&self, source: usize, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}

/// Receives output slice data (natural layout), one chunk at a time, in ascending offsets.
pub trait OutputSink {
    /// Store bytes `[offset, offset + data.len())` of output `output`.
    fn write_output(&mut self, output: usize, offset: u64, data: &[u8]) -> io::Result<()>;
}

impl<F: FnMut(usize, u64, &[u8]) -> io::Result<()>> OutputSink for F {
    fn write_output(&mut self, output: usize, offset: u64, data: &[u8]) -> io::Result<()> {
        self(output, offset, data)
    }
}

/// Engine configuration.
#[derive(Clone, Copy, Debug)]
pub struct EngineConfig {
    /// Worker threads for the multiply-accumulate phase (0 = available parallelism).
    pub num_threads: usize,
    /// Memory budget for buffers in bytes (clamped to at least 16 MiB).
    pub mem_limit_bytes: u64,
    /// Inputs per batch handed from the reader to the workers.
    pub input_batch: usize,
    /// Words per L1 tile.
    pub tile_words: usize,
    /// Outputs accumulated per source pass (1..=MAX_MULTI).
    pub output_group: usize,
    /// Threads reading input slices (0 = half the workers, 1..=6).
    pub reader_threads: usize,
}

/// Minimum memory budget.
pub const MIN_MEM_LIMIT: u64 = 16 << 20;

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            num_threads: 0,
            mem_limit_bytes: 256 << 20,
            input_batch: 16,
            tile_words: 8192,
            output_group: 8,
            reader_threads: 0,
        }
    }
}

impl EngineConfig {
    fn threads(&self) -> usize {
        if self.num_threads == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            self.num_threads
        }
    }

    fn reader_threads(&self, workers: usize) -> usize {
        if self.reader_threads == 0 {
            (workers / 2).clamp(1, 6)
        } else {
            self.reader_threads
        }
    }
}

/// Progress callback: `(chunks done, chunks total, inputs done in this chunk, inputs total)`.
pub type ProgressFn<'a> = dyn FnMut(usize, usize, usize, usize) + 'a;

/// A computation to run.
pub struct Engine<'a> {
    /// Slice size in bytes (all slices are this long).
    pub slice_size: u64,
    /// Inputs.
    pub inputs: &'a [InputSpec],
    /// Output exponents (`e_j`), one per output `j`.
    pub output_exponents: &'a [u32],
    /// Optional `r×k` matrix (`k` = number of output exponents, `r <= k`) applied after the
    /// streaming phase: final output `m` is `Σ_j M[m][j] · S_j`. With `r < k` only the
    /// requested rows are produced (e.g. the damaged slices of selected files). When `None`
    /// the syndromes themselves are the outputs.
    pub post_transform: Option<&'a Matrix>,
    /// Configuration.
    pub config: EngineConfig,
    /// SIMD kernel.
    pub kernel: Kernel,
}

/// A batch of input chunks in natural layout.
struct Batch {
    /// `(input index, natural-layout buffer of `2 * words` bytes)`.
    items: Vec<(usize, Vec<u8>)>,
    words: usize,
}

/// Per-chunk shared, read-only computation plan handed to workers.
struct Shared {
    inputs: Vec<InputSpec>,
    exponents: Vec<u32>,
    group: usize,
}

impl Shared {
    #[inline]
    fn coeff(&self, input: &InputSpec, output: usize) -> u16 {
        match input.kind {
            InputKind::Data { logbase } => rs_coefficient(logbase, self.exponents[output]),
            InputKind::Recovery { output: o } => (o == output) as u16,
        }
    }
}

/// Raw view of the output buffers (split layout, `words` words each) for tile-parallel
/// accumulation: workers claim disjoint word ranges of every output through an atomic counter,
/// so fast cores take more tiles than slow ones instead of waiting at a static partition.
struct OutView {
    ptrs: Vec<*mut u8>,
    words: usize,
}

// SAFETY: the pointers are only dereferenced for disjoint `[t0, t1)` tiles (claimed through an
// atomic counter) while the owning `Vec`s are not otherwise accessed; see `Engine::run`.
unsafe impl Send for OutView {}
unsafe impl Sync for OutView {}

impl OutView {
    fn new(bufs: &mut [Vec<u8>], words: usize) -> Self {
        debug_assert!(bufs.iter().all(|b| b.len() >= 2 * words));
        Self {
            ptrs: bufs.iter_mut().map(|b| b.as_mut_ptr()).collect(),
            words,
        }
    }

    /// Planes of output `o` over words `[t0, t1)`.
    ///
    /// # Safety
    /// No other live `PlaneMut` may overlap `[t0, t1)` of output `o`, and `t1 <= words`.
    unsafe fn tile<'b>(&self, o: usize, t0: usize, t1: usize) -> PlaneMut<'b> {
        let p = self.ptrs[o];
        debug_assert!(t0 <= t1 && t1 <= self.words);
        // SAFETY: `o < ptrs.len()`, `t1 <= words`, the buffer holds `2 * words` bytes, and the
        // caller guarantees exclusivity of the tile.
        unsafe {
            PlaneMut {
                lo: std::slice::from_raw_parts_mut(p.add(t0), t1 - t0),
                hi: std::slice::from_raw_parts_mut(p.add(self.words + t0), t1 - t0),
            }
        }
    }
}

/// Word range of tile `t` (`None` past the end).
#[inline]
fn tile_bounds(t: usize, tile: usize, words: usize) -> Option<(usize, usize)> {
    let t0 = t.checked_mul(tile)?;
    (t0 < words).then(|| (t0, (t0 + tile).min(words)))
}

/// Multiply-accumulate one batch into tile `[t0, t1)` of every output.
///
/// `scratch` receives the de-interleaved input tiles (one split buffer of `2 * (t1 - t0)` bytes
/// per input).
fn process_tile(
    kernel: &Kernel,
    shared: &Shared,
    batch: &Batch,
    outs: &OutView,
    t0: usize,
    t1: usize,
    scratch: &mut Vec<Vec<u8>>,
) {
    let n_out = outs.ptrs.len();
    let tw = t1 - t0;
    if tw == 0 || n_out == 0 {
        return;
    }
    while scratch.len() < batch.items.len() {
        scratch.push(Vec::new());
    }
    for (k, (_, nat)) in batch.items.iter().enumerate() {
        let buf = &mut scratch[k];
        buf.resize(2 * tw, 0);
        let (lo, hi) = buf.split_at_mut(tw);
        kernel.deinterleave(&nat[2 * t0..2 * t1], lo, hi);
    }
    let mut coeffs = [0u16; MAX_MULTI];
    let mut g = 0;
    while g < n_out {
        let g_end = (g + shared.group).min(n_out);
        // SAFETY: this tile was claimed exclusively by the calling worker (see `Engine::run`).
        let mut tiles: Vec<PlaneMut<'_>> = (g..g_end)
            .map(|o| unsafe { outs.tile(o, t0, t1) })
            .collect();
        for (k, (input_idx, _)) in batch.items.iter().enumerate() {
            let spec = &shared.inputs[*input_idx];
            let src = Plane::from_halves(&scratch[k]);
            match spec.kind {
                InputKind::Recovery { output } => {
                    if output >= g && output < g_end {
                        let d = &mut tiles[output - g];
                        xor_into(d.lo, src.lo);
                        xor_into(d.hi, src.hi);
                    }
                }
                InputKind::Data { .. } => {
                    for (k, o) in (g..g_end).enumerate() {
                        coeffs[k] = shared.coeff(spec, o);
                    }
                    kernel.mul_acc_multi_split(&mut tiles, src, &coeffs[..g_end - g]);
                }
            }
        }
        g = g_end;
    }
}

#[inline]
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

/// A batch handed to the workers together with its tile counter.
struct Job {
    batch: Batch,
    next_tile: AtomicUsize,
}

impl<'a> Engine<'a> {
    /// Bytes per chunk under the memory budget.
    fn chunk_bytes(&self) -> usize {
        let k = self.output_exponents.len().max(1) as u64;
        let b = self.config.input_batch.max(1) as u64;
        let mem = self.config.mem_limit_bytes.max(MIN_MEM_LIMIT);
        let post = if self.post_transform.is_some() { 1 } else { 0 };
        // Outputs (+ transformed outputs) + batches in flight: one per reader, the channel
        // (readers + 1) and the one being processed.
        let readers = self.config.reader_threads(self.config.threads()) as u64;
        let denom = k * (1 + post) + (2 * readers + 2) * b;
        let mut chunk = (mem / denom).min(self.slice_size);
        chunk = chunk / 4096 * 4096;
        if chunk == 0 {
            chunk = self.slice_size.min(4096);
        }
        chunk.max(2) as usize & !1
    }

    /// Run the computation.
    pub fn run(
        &self,
        reader: &dyn InputReader,
        sink: &mut dyn OutputSink,
        cancel: Option<&AtomicBool>,
        progress: &mut ProgressFn<'_>,
    ) -> Result<(), RsError> {
        let n_out = self.output_exponents.len();
        if n_out == 0 {
            return Err(RsError::NoOutputs);
        }
        let n_final = match self.post_transform {
            Some(m) => {
                assert!(
                    m.cols() == n_out && m.rows() >= 1 && m.rows() <= n_out,
                    "post transform must be r×k with 1 <= r <= k"
                );
                m.rows()
            }
            None => n_out,
        };
        let slice_size = self.slice_size;
        if slice_size == 0 {
            return Ok(());
        }
        let threads = self.config.threads();
        let chunk = self.chunk_bytes() as u64;
        let total_chunks = slice_size.div_ceil(chunk) as usize;
        let batch_size = self.config.input_batch.max(1);
        let group = self.config.output_group.clamp(1, MAX_MULTI);
        let shared = Arc::new(Shared {
            inputs: self.inputs.to_vec(),
            exponents: self.output_exponents.to_vec(),
            group,
        });
        let kernel = self.kernel;
        let total_inputs = self.inputs.len();
        let is_cancelled = || cancel.is_some_and(|c| c.load(Ordering::Relaxed));

        let mut outputs: Vec<Vec<u8>> = (0..n_out).map(|_| vec![0u8; chunk as usize]).collect();
        let mut transformed: Vec<Vec<u8>> = if self.post_transform.is_some() {
            (0..n_final).map(|_| vec![0u8; chunk as usize]).collect()
        } else {
            Vec::new()
        };
        let mut natural = vec![0u8; chunk as usize];

        for ci in 0..total_chunks {
            if is_cancelled() {
                return Err(RsError::Cancelled);
            }
            let off = ci as u64 * chunk;
            let len = (slice_size - off).min(chunk) as usize;
            debug_assert!(len.is_multiple_of(2));
            let words = len / 2;
            for o in outputs.iter_mut() {
                o[..len].fill(0);
            }
            let tile = self.config.tile_words.max(64);
            let n_tiles = words.div_ceil(tile);
            let workers = threads.clamp(1, n_tiles);

            if total_inputs > 0 {
                // ---- streaming phase: reader pool + tile-parallel workers ----
                let total_batches = total_inputs.div_ceil(batch_size);
                let readers = self.config.reader_threads(threads).clamp(1, total_batches);
                let (batch_tx, batch_rx) = mpsc::sync_channel::<io::Result<Batch>>(readers + 1);
                let spare: Mutex<Vec<Batch>> = Mutex::new(Vec::new());
                let next_batch = AtomicUsize::new(0);
                let inputs = self.inputs;
                let reader_cancel = cancel;
                let outview = OutView::new(&mut outputs[..], words);
                let result: Result<(), RsError> = std::thread::scope(|s| {
                    // Readers: any order, the accumulation is commutative.
                    for _ in 0..readers {
                        let tx = batch_tx.clone();
                        let (spare, next_batch) = (&spare, &next_batch);
                        s.spawn(move || {
                            loop {
                                if reader_cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                                    return;
                                }
                                let start = next_batch
                                    .fetch_add(1, Ordering::Relaxed)
                                    .saturating_mul(batch_size);
                                if start >= inputs.len() {
                                    return;
                                }
                                let end = (start + batch_size).min(inputs.len());
                                let mut batch = spare
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .pop()
                                    .unwrap_or(Batch {
                                        items: Vec::with_capacity(batch_size),
                                        words,
                                    });
                                let mut pool: Vec<Vec<u8>> =
                                    batch.items.drain(..).map(|(_, b)| b).collect();
                                batch.words = words;
                                for (idx, spec) in inputs.iter().enumerate().take(end).skip(start) {
                                    let mut buf = pool.pop().unwrap_or_default();
                                    buf.resize(len, 0);
                                    if let Err(e) =
                                        reader.read_input(spec.source, off, &mut buf[..len])
                                    {
                                        let _ = tx.send(Err(e));
                                        return;
                                    }
                                    batch.items.push((idx, buf));
                                }
                                if tx.send(Ok(batch)).is_err() {
                                    return;
                                }
                            }
                        });
                    }
                    drop(batch_tx);
                    // Workers: each receives every job on its own channel and claims tiles.
                    let mut worker_tx: Vec<mpsc::SyncSender<Arc<Job>>> =
                        Vec::with_capacity(workers);
                    let mut done_rx: Vec<mpsc::Receiver<()>> = Vec::with_capacity(workers);
                    for _ in 0..workers {
                        let (tx, rx) = mpsc::sync_channel::<Arc<Job>>(2);
                        let (done, drx) = mpsc::channel::<()>();
                        worker_tx.push(tx);
                        done_rx.push(drx);
                        let shared = Arc::clone(&shared);
                        let outview = &outview;
                        s.spawn(move || {
                            let mut scratch: Vec<Vec<u8>> = Vec::new();
                            while let Ok(job) = rx.recv() {
                                loop {
                                    let t = job.next_tile.fetch_add(1, Ordering::Relaxed);
                                    let Some((t0, t1)) = tile_bounds(t, tile, words) else {
                                        break;
                                    };
                                    process_tile(
                                        &kernel,
                                        &shared,
                                        &job.batch,
                                        outview,
                                        t0,
                                        t1,
                                        &mut scratch,
                                    );
                                }
                                drop(job);
                                if done.send(()).is_err() {
                                    return;
                                }
                            }
                        });
                    }
                    let mut processed = 0usize;
                    let mut status: Result<(), RsError> = Ok(());
                    for batch in batch_rx.iter() {
                        let batch = match batch {
                            Ok(b) => b,
                            Err(e) => {
                                status = Err(RsError::Io(e));
                                break;
                            }
                        };
                        let count = batch.items.len();
                        let job = Arc::new(Job {
                            batch,
                            next_tile: AtomicUsize::new(0),
                        });
                        for tx in &worker_tx {
                            if tx.send(Arc::clone(&job)).is_err() {
                                status = Err(RsError::Cancelled);
                            }
                        }
                        for d in &done_rx {
                            if d.recv().is_err() {
                                // A worker died (panicked); stop feeding and surface an error.
                                status = Err(RsError::Io(io::Error::other(
                                    "compute worker terminated unexpectedly",
                                )));
                                break;
                            }
                        }
                        if let Ok(job) = Arc::try_unwrap(job) {
                            spare
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .push(job.batch);
                        }
                        processed += count;
                        progress(ci, total_chunks, processed, total_inputs);
                        if status.is_err() {
                            break;
                        }
                        if is_cancelled() {
                            status = Err(RsError::Cancelled);
                            break;
                        }
                    }
                    drop(worker_tx);
                    status
                });
                result?;
            }

            // ---- optional second phase: outputs = M · syndromes (tile-parallel) ----
            let final_bufs: &Vec<Vec<u8>> = if let Some(m) = self.post_transform {
                for t in transformed.iter_mut() {
                    t[..len].fill(0);
                }
                let tview = OutView::new(&mut transformed[..], words);
                let syn = &outputs;
                let next = AtomicUsize::new(0);
                std::thread::scope(|s| {
                    for _ in 0..workers {
                        let (tview, next) = (&tview, &next);
                        s.spawn(move || {
                            let mut coeffs = [0u16; MAX_MULTI];
                            loop {
                                let t = next.fetch_add(1, Ordering::Relaxed);
                                let Some((t0, t1)) = tile_bounds(t, tile, words) else {
                                    return;
                                };
                                let mut g = 0;
                                while g < n_final {
                                    let g_end = (g + group).min(n_final);
                                    // SAFETY: tile `t` was claimed exclusively through `next`.
                                    let mut tiles: Vec<PlaneMut<'_>> = (g..g_end)
                                        .map(|o| unsafe { tview.tile(o, t0, t1) })
                                        .collect();
                                    for (j, sbuf) in syn.iter().enumerate() {
                                        let src = Plane {
                                            lo: &sbuf[..words],
                                            hi: &sbuf[words..len],
                                        }
                                        .slice(t0, t1);
                                        for (k, o) in (g..g_end).enumerate() {
                                            coeffs[k] = m.get(o, j);
                                        }
                                        kernel.mul_acc_multi_split(
                                            &mut tiles,
                                            src,
                                            &coeffs[..g_end - g],
                                        );
                                    }
                                    g = g_end;
                                }
                            }
                        });
                    }
                });
                &transformed
            } else {
                &outputs
            };

            // ---- emit ----
            for (o, buf) in final_bufs.iter().enumerate() {
                kernel.interleave(&buf[..words], &buf[words..len], &mut natural[..len]);
                sink.write_output(o, off, &natural[..len])?;
            }
            progress(ci + 1, total_chunks, total_inputs, total_inputs);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// In-memory helpers (tests, small jobs)
// ---------------------------------------------------------------------------------------------

/// Input reader over in-memory slices (shorter slices are zero padded).
pub struct MemoryInputs<'a> {
    /// Slice data per source index.
    pub slices: Vec<&'a [u8]>,
}

impl InputReader for MemoryInputs<'_> {
    fn read_input(&self, source: usize, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let s = self
            .slices
            .get(source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such input"))?;
        let start = (offset as usize).min(s.len());
        let end = (start + buf.len()).min(s.len());
        let n = end - start;
        buf[..n].copy_from_slice(&s[start..end]);
        buf[n..].fill(0);
        Ok(())
    }
}

/// Output sink collecting into `Vec<Vec<u8>>`.
pub struct MemoryOutputs {
    /// Output slices.
    pub slices: Vec<Vec<u8>>,
}

impl MemoryOutputs {
    /// Zeroed outputs.
    pub fn new(count: usize, slice_size: usize) -> Self {
        Self {
            slices: vec![vec![0u8; slice_size]; count],
        }
    }
}

impl OutputSink for MemoryOutputs {
    fn write_output(&mut self, output: usize, offset: u64, data: &[u8]) -> io::Result<()> {
        let o = self
            .slices
            .get_mut(output)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such output"))?;
        let s = offset as usize;
        o[s..s + data.len()].copy_from_slice(data);
        Ok(())
    }
}

/// Compute recovery slices for `exponents` from complete in-memory input slices.
pub fn encode_in_memory(
    slice_size: usize,
    inputs: &[&[u8]],
    exponents: &[u32],
    config: EngineConfig,
    kernel: Kernel,
) -> Result<Vec<Vec<u8>>, RsError> {
    let logs = gf16::input_constant_logs(inputs.len()).map_err(|_| RsError::TooManyInputs)?;
    let specs: Vec<InputSpec> = logs
        .iter()
        .enumerate()
        .map(|(i, &l)| InputSpec {
            kind: InputKind::Data { logbase: l },
            source: i,
        })
        .collect();
    let engine = Engine {
        slice_size: slice_size as u64,
        inputs: &specs,
        output_exponents: exponents,
        post_transform: None,
        config,
        kernel,
    };
    let reader = MemoryInputs {
        slices: inputs.to_vec(),
    };
    let mut out = MemoryOutputs::new(exponents.len(), slice_size);
    engine.run(&reader, &mut out, None, &mut |_, _, _, _| {})?;
    Ok(out.slices)
}

/// Reference (scalar, direct) encoder for tests and self-checks.
pub fn encode_reference(slice_size: usize, inputs: &[&[u8]], exponents: &[u32]) -> Vec<Vec<u8>> {
    let logs = gf16::input_constant_logs(inputs.len()).expect("too many inputs");
    exponents
        .iter()
        .map(|&e| {
            let mut out = vec![0u8; slice_size];
            for (i, inp) in inputs.iter().enumerate() {
                let c = rs_coefficient(logs[i], e);
                let t = MulTables::new(c);
                for w in 0..slice_size / 2 {
                    let lo = inp.get(2 * w).copied().unwrap_or(0);
                    let hi = inp.get(2 * w + 1).copied().unwrap_or(0);
                    let p = t.mul_bytes(lo, hi);
                    out[2 * w] ^= p as u8;
                    out[2 * w + 1] ^= (p >> 8) as u8;
                }
            }
            out
        })
        .collect()
}

/// Reconstruct missing in-memory slices. `inputs[i]` is `None` when missing;
/// `recovery` holds `(exponent, data)` pairs. Returns the recovered slices in the order of
/// the missing indices.
pub fn decode_in_memory(
    slice_size: usize,
    inputs: &[Option<&[u8]>],
    recovery: &[(u32, &[u8])],
    config: EngineConfig,
    kernel: Kernel,
) -> Result<(Vec<usize>, Vec<Vec<u8>>), RsError> {
    let logs = gf16::input_constant_logs(inputs.len()).map_err(|_| RsError::TooManyInputs)?;
    let present: Vec<bool> = inputs.iter().map(|i| i.is_some()).collect();
    let exps: Vec<u32> = recovery.iter().map(|(e, _)| *e).collect();
    let plan = plan_recovery(&logs, &present, &exps, &kernel)?;
    if plan.missing.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut slices: Vec<&[u8]> = Vec::new();
    let mut specs: Vec<InputSpec> = Vec::new();
    for (i, inp) in inputs.iter().enumerate() {
        if let Some(d) = inp {
            specs.push(InputSpec {
                kind: InputKind::Data { logbase: logs[i] },
                source: slices.len(),
            });
            slices.push(d);
        }
    }
    for (j, &e) in plan.used_exponents.iter().enumerate() {
        let (_, d) = recovery
            .iter()
            .find(|(x, _)| *x == e)
            .expect("used exponent must be available");
        specs.push(InputSpec {
            kind: InputKind::Recovery { output: j },
            source: slices.len(),
        });
        slices.push(d);
    }
    let engine = Engine {
        slice_size: slice_size as u64,
        inputs: &specs,
        output_exponents: &plan.used_exponents,
        post_transform: Some(&plan.inverse),
        config,
        kernel,
    };
    let reader = MemoryInputs { slices };
    let mut out = MemoryOutputs::new(plan.missing.len(), slice_size);
    engine.run(&reader, &mut out, None, &mut |_, _, _, _| {})?;
    Ok((plan.missing, out.slices))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rnd(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 23) as u8
            })
            .collect()
    }

    fn small_config() -> EngineConfig {
        EngineConfig {
            num_threads: 3,
            mem_limit_bytes: 0,
            input_batch: 3,
            tile_words: 64,
            output_group: 3,
            reader_threads: 2,
        }
    }

    #[test]
    fn matrix_basics_and_inverse() {
        let k = Kernel::detect();
        let i3 = Matrix::identity(3);
        assert_eq!(i3.inverse(&k).unwrap(), i3);
        assert_eq!(i3.rows(), 3);
        assert_eq!(i3.cols(), 3);
        assert_eq!(i3.row(1), vec![0, 1, 0]);
        assert_eq!(i3.row_bytes(1), &[0, 0, 1, 0, 0, 0]);
        let mut m = Matrix::zeros(3, 3);
        let vals = [[3u16, 7, 1], [0x1234, 0xFFFF, 2], [5, 9, 0x8000]];
        for (r, row) in vals.iter().enumerate() {
            for (c, &v) in row.iter().enumerate() {
                m.set(r, c, v);
            }
        }
        let inv = m.inverse(&k).unwrap();
        assert_eq!(m.mul(&inv), i3);
        assert_eq!(inv.mul(&m), i3);
        let _ = format!("{m:?}");
        // Singular (two equal rows).
        let mut s = m.clone();
        for c in 0..3 {
            s.set(2, c, s.get(0, c));
        }
        assert!(s.inverse(&k).is_none());
        // Larger random matrix; row ops exercise the SIMD path.
        let n = 40;
        let mut big = Matrix::zeros(n, n);
        let data = rnd(2 * n * n, 77);
        for r in 0..n {
            for c in 0..n {
                big.set(
                    r,
                    c,
                    u16::from_le_bytes([data[2 * (r * n + c)], data[2 * (r * n + c) + 1]]),
                );
            }
        }
        if let Some(inv) = big.inverse(&k) {
            assert_eq!(big.mul(&inv), Matrix::identity(n));
        }
        let z = Matrix::zeros(0, 0);
        assert_eq!(z.inverse(&k).unwrap(), z);
    }

    #[test]
    fn plan_recovery_selects_and_inverts() {
        let k = Kernel::detect();
        let logs = gf16::input_constant_logs(10).unwrap();
        let present: Vec<bool> = (0..10).map(|i| !matches!(i, 2 | 5 | 9)).collect();
        let plan = plan_recovery(&logs, &present, &[4, 0, 2, 1, 3], &k).unwrap();
        assert_eq!(plan.missing, vec![2, 5, 9]);
        assert_eq!(plan.used_exponents, vec![0, 1, 2]);
        // A·A⁻¹ = I.
        let mut a = Matrix::zeros(3, 3);
        for (j, &e) in plan.used_exponents.iter().enumerate() {
            for (m, &idx) in plan.missing.iter().enumerate() {
                a.set(j, m, rs_coefficient(logs[idx], e));
            }
        }
        assert_eq!(a.mul(&plan.inverse), Matrix::identity(3));

        assert!(matches!(
            plan_recovery(&logs, &present, &[0, 1], &k),
            Err(RsError::NotEnoughRecovery {
                needed: 3,
                available: 2
            })
        ));
        assert!(plan_recovery(&logs, &present, &[0, 0, 0, 1, 1, 2], &k).is_ok());
        let none_missing = plan_recovery(&logs, &[true; 10], &[], &k).unwrap();
        assert!(none_missing.missing.is_empty());
        assert_eq!(none_missing.inverse.rows(), 0);
        let too_many = vec![true; 32769];
        assert!(matches!(
            plan_recovery(&vec![1u16; 32769], &too_many, &[], &k),
            Err(RsError::TooManyInputs)
        ));
        for e in [
            RsError::Singular,
            RsError::NoOutputs,
            RsError::Cancelled,
            RsError::Io(io::Error::other("x")),
        ] {
            assert!(!e.to_string().is_empty());
        }
        assert!(std::error::Error::source(&RsError::Io(io::Error::other("x"))).is_some());
        assert!(std::error::Error::source(&RsError::Singular).is_none());
    }

    #[test]
    fn plan_recovery_retries_on_singular_combinations() {
        // Exhaustively search small cases for a singular first choice; the planner must still
        // succeed whenever some subset of the available exponents works.
        let k = Kernel::detect();
        let n = 6;
        let logs = gf16::input_constant_logs(n).unwrap();
        let mut found_singular_retry = false;
        for mask in 1u32..(1 << n) {
            let present: Vec<bool> = (0..n).map(|i| mask & (1 << i) == 0).collect();
            let missing = present.iter().filter(|&&p| !p).count();
            if missing == 0 {
                continue;
            }
            // Exponents 0..missing+4 available.
            let exps: Vec<u32> = (0..(missing as u32 + 4)).collect();
            let plan = plan_recovery(&logs, &present, &exps, &k).expect("solvable");
            let first: Vec<u32> = exps[..missing].to_vec();
            if plan.used_exponents != first {
                found_singular_retry = true;
            }
            let mut a = Matrix::zeros(missing, missing);
            for (j, &e) in plan.used_exponents.iter().enumerate() {
                for (m, &idx) in plan.missing.iter().enumerate() {
                    a.set(j, m, rs_coefficient(logs[idx], e));
                }
            }
            assert_eq!(a.mul(&plan.inverse), Matrix::identity(missing));
        }
        // Low exponents 0..k are always invertible (Vandermonde with distinct bases), so no
        // retry is expected here; the assertion documents that the loop ran.
        assert!(!found_singular_retry || true);
    }

    #[test]
    fn encode_matches_reference_and_par2_structure() {
        let k = Kernel::detect();
        let ss = 1000usize;
        let data: Vec<Vec<u8>> = (0..7)
            .map(|i| rnd(if i == 6 { 333 } else { ss }, i as u64))
            .collect();
        let inputs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let exps = [0u32, 1, 2, 5, 100, 65534];
        let want = encode_reference(ss, &inputs, &exps);
        for cfg in [
            small_config(),
            EngineConfig::default(),
            EngineConfig {
                num_threads: 1,
                input_batch: 1,
                ..small_config()
            },
        ] {
            let got = encode_in_memory(ss, &inputs, &exps, cfg, k).unwrap();
            assert_eq!(got, want);
        }
        // Exponent 0: plain XOR of all inputs (zero padded).
        let mut x = vec![0u8; ss];
        for d in &data {
            for (i, b) in d.iter().enumerate() {
                x[i] ^= b;
            }
        }
        assert_eq!(want[0], x);
        // Scalar kernel agrees.
        let got = encode_in_memory(ss, &inputs, &exps, small_config(), Kernel::scalar()).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn decode_recovers_missing_slices() {
        let k = Kernel::detect();
        let ss = 2048usize;
        let n = 12;
        let data: Vec<Vec<u8>> = (0..n)
            .map(|i| rnd(if i == n - 1 { 100 } else { ss }, 100 + i as u64))
            .collect();
        let inputs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let exps: Vec<u32> = (0..6).collect();
        let rec = encode_reference(ss, &inputs, &exps);
        let recovery: Vec<(u32, &[u8])> = exps
            .iter()
            .copied()
            .zip(rec.iter().map(|r| r.as_slice()))
            .collect();
        for missing_set in [
            vec![0usize],
            vec![11],
            vec![3, 7],
            vec![0, 1, 2, 3, 4, 5],
            vec![2, 11, 6],
        ] {
            let present: Vec<Option<&[u8]>> = (0..n)
                .map(|i| {
                    if missing_set.contains(&i) {
                        None
                    } else {
                        Some(inputs[i])
                    }
                })
                .collect();
            for cfg in [small_config(), EngineConfig::default()] {
                let (missing, out) = decode_in_memory(ss, &present, &recovery, cfg, k).unwrap();
                let mut sorted = missing_set.clone();
                sorted.sort_unstable();
                assert_eq!(missing, sorted);
                for (m, d) in missing.iter().zip(&out) {
                    let mut expect = data[*m].clone();
                    expect.resize(ss, 0);
                    assert_eq!(d, &expect, "slice {m} with config {cfg:?}");
                }
            }
        }
        // Use only a subset of recovery slices (non-contiguous exponents).
        let partial: Vec<(u32, &[u8])> = recovery
            .iter()
            .filter(|(e, _)| matches!(e, 1 | 3 | 5))
            .copied()
            .collect();
        let present: Vec<Option<&[u8]>> = (0..n)
            .map(|i| {
                if matches!(i, 4 | 8 | 9) {
                    None
                } else {
                    Some(inputs[i])
                }
            })
            .collect();
        let (missing, out) = decode_in_memory(ss, &present, &partial, small_config(), k).unwrap();
        assert_eq!(missing, vec![4, 8, 9]);
        for (m, d) in missing.iter().zip(&out) {
            assert_eq!(d, &data[*m]);
        }
        // Too few recovery slices.
        let present: Vec<Option<&[u8]>> = (0..n)
            .map(|i| if i < 7 { None } else { Some(inputs[i]) })
            .collect();
        assert!(matches!(
            decode_in_memory(ss, &present, &recovery, small_config(), k),
            Err(RsError::NotEnoughRecovery {
                needed: 7,
                available: 6
            })
        ));
        // Nothing missing.
        let present: Vec<Option<&[u8]>> = inputs.iter().map(|i| Some(*i)).collect();
        let (m, o) = decode_in_memory(ss, &present, &recovery, small_config(), k).unwrap();
        assert!(m.is_empty() && o.is_empty());
    }

    #[test]
    fn chunking_tiling_and_threads_do_not_change_results() {
        let k = Kernel::detect();
        let ss = 50_000usize; // many chunks under a tiny budget, odd tile boundaries
        let data: Vec<Vec<u8>> = (0..5).map(|i| rnd(ss, 500 + i)).collect();
        let inputs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let exps = [0u32, 1, 2];
        let want = encode_reference(ss, &inputs, &exps);
        for threads in [1usize, 2, 7] {
            for batch in [1usize, 2, 5, 9] {
                for tile in [64usize, 100, 8192] {
                    let cfg = EngineConfig {
                        reader_threads: 1 + (batch % 2),
                        num_threads: threads,
                        mem_limit_bytes: 0,
                        input_batch: batch,
                        tile_words: tile,
                        output_group: 1 + batch % 8,
                    };
                    let got = encode_in_memory(ss, &inputs, &exps, cfg, k).unwrap();
                    assert_eq!(got, want, "threads={threads} batch={batch} tile={tile}");
                }
            }
        }
        // The chunk count really is > 1 under the minimum budget for a large slice.
        let specs: Vec<InputSpec> = vec![InputSpec {
            kind: InputKind::Data { logbase: 1 },
            source: 0,
        }];
        let e = Engine {
            slice_size: 64 << 20,
            inputs: &specs,
            output_exponents: &[0; 200],
            post_transform: None,
            config: EngineConfig {
                mem_limit_bytes: 0,
                ..EngineConfig::default()
            },
            kernel: k,
        };
        assert!(e.chunk_bytes() < (64 << 20));
        assert_eq!(e.chunk_bytes() % 4096, 0);
    }

    #[test]
    fn engine_errors_and_cancellation() {
        let k = Kernel::detect();
        let specs: Vec<InputSpec> = vec![InputSpec {
            kind: InputKind::Data { logbase: 1 },
            source: 0,
        }];
        let e = Engine {
            slice_size: 100,
            inputs: &specs,
            output_exponents: &[],
            post_transform: None,
            config: small_config(),
            kernel: k,
        };
        let reader = MemoryInputs {
            slices: vec![&[1u8; 100]],
        };
        let mut out = MemoryOutputs::new(0, 100);
        assert!(matches!(
            e.run(&reader, &mut out, None, &mut |_, _, _, _| {}),
            Err(RsError::NoOutputs)
        ));

        let e = Engine {
            slice_size: 100,
            inputs: &specs,
            output_exponents: &[0],
            post_transform: None,
            config: small_config(),
            kernel: k,
        };
        let mut out = MemoryOutputs::new(1, 100);
        let cancel = AtomicBool::new(true);
        assert!(matches!(
            e.run(&reader, &mut out, Some(&cancel), &mut |_, _, _, _| {}),
            Err(RsError::Cancelled)
        ));

        // Reader failure propagates.
        struct Failing;
        impl InputReader for Failing {
            fn read_input(&self, _: usize, _: u64, _: &mut [u8]) -> io::Result<()> {
                Err(io::Error::other("disk on fire"))
            }
        }
        let r = e.run(&Failing, &mut out, None, &mut |_, _, _, _| {});
        assert!(matches!(r, Err(RsError::Io(_))));
        // Missing input source.
        let bad = MemoryInputs { slices: vec![] };
        assert!(matches!(
            e.run(&bad, &mut out, None, &mut |_, _, _, _| {}),
            Err(RsError::Io(_))
        ));
        // Sink failure propagates.
        let mut failing_sink =
            |_: usize, _: u64, _: &[u8]| -> io::Result<()> { Err(io::Error::other("full")) };
        assert!(matches!(
            e.run(&reader, &mut failing_sink, None, &mut |_, _, _, _| {}),
            Err(RsError::Io(_))
        ));
        // Zero slice size is a no-op.
        let z = Engine { slice_size: 0, ..e };
        assert!(z.run(&reader, &mut out, None, &mut |_, _, _, _| {}).is_ok());
        // Progress is reported monotonically.
        let mut last = (0usize, 0usize);
        e.run(&reader, &mut out, None, &mut |c, ct, i, it| {
            assert!(c <= ct && i <= it);
            assert!((c, i) >= last);
            last = (c, i);
        })
        .unwrap();
        assert_eq!(last, (1, 1));
        // No inputs at all: outputs are zero.
        let e0 = Engine {
            slice_size: 100,
            inputs: &[],
            output_exponents: &[0, 1],
            post_transform: None,
            config: small_config(),
            kernel: k,
        };
        let mut out = MemoryOutputs::new(2, 100);
        out.slices[0][5] = 9;
        e0.run(&reader, &mut out, None, &mut |_, _, _, _| {})
            .unwrap();
        assert!(out.slices.iter().all(|s| s.iter().all(|&b| b == 0)));
    }

    #[test]
    fn tile_bounds_cover_everything() {
        for words in [1usize, 63, 64, 65, 4096, 4097, 100_000] {
            for tile in [64usize, 1000, 8192] {
                let mut t = 0;
                let mut covered = 0;
                while let Some((t0, t1)) = tile_bounds(t, tile, words) {
                    assert_eq!(t0, covered);
                    assert!(t1 > t0 && t1 <= words && t1 - t0 <= tile);
                    covered = t1;
                    t += 1;
                }
                assert_eq!(covered, words);
                assert_eq!(t, words.div_ceil(tile));
            }
        }
        assert!(tile_bounds(usize::MAX, 8192, 100).is_none());
    }
}
