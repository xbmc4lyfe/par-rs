//! Zero-copy deep introspection of PAR2 v2.0 buffers plus PAR1 / PAR3 header detection.
//!
//! [`inspect_par2`] walks a byte buffer (typically the decoded articles of a `.par2` file or the
//! head of a `.volNNN+MM.par2` volume) and classifies every packet of the twelve PAR2 v2.0
//! packet types, resynchronising on the `PAR2\0PKT` magic after garbage, truncation, or a
//! corrupt header. Nothing is copied out of the buffer except the small decoded fields; slice
//! payloads are reported as `(offset, length)` ranges. Every field is bounds checked: a
//! truncated or adversarial buffer yields a partial report, never a panic.
//!
//! Also here: creator fingerprinting ([`CreatorInfo`]), `.volNNN+MM.par2` name analysis
//! ([`Par2FileName`]) and PAR1 / PAR3 header detection ([`detect_format`]).

use crate::bytes::{array, take, trim_nul, u32_le, u64_le};
use md5::{Digest, Md5};
use std::fmt;

/// Packet magic.
pub const PAR2_MAGIC: [u8; 8] = *b"PAR2\0PKT";
/// PAR3 packet magic.
pub const PAR3_MAGIC: [u8; 8] = *b"PAR3\0PKT";
/// PAR1 file magic (`PAR` followed by five NULs).
pub const PAR1_MAGIC: [u8; 8] = *b"PAR\0\0\0\0\0";
/// PAR2 packet header length.
pub const HEADER_LEN: usize = 64;
/// Hashed prefix of an exponent-0 recovery slice used as its fingerprint.
pub const EXP0_PREFIX_LEN: usize = 16 * 1024;

/// The twelve PAR2 v2.0 packet types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PacketKind {
    /// `Main`: slice size and file ids.
    Main,
    /// `FileDesc`: file id, hashes, length, name.
    FileDesc,
    /// `IFSC`: per-slice MD5 + CRC-32 of an input file.
    Ifsc,
    /// `RecvSlic`: a recovery slice.
    RecvSlic,
    /// `Creator`: client string.
    Creator,
    /// `UniFileN`: `UTF-16LE` filename.
    UniFileN,
    /// `CommASCI`: `ASCII` comment.
    CommAsci,
    /// `CommUni`: `UTF-16LE` comment.
    CommUni,
    /// `FileSlic`: an input file slice stored inside the par2 set.
    FileSlic,
    /// `RFSC`: recovery file slice checksums.
    Rfsc,
    /// `PkdMain`: packed main packet (sub-slice size).
    PkdMain,
    /// `PkdRecvS`: packed recovery slice.
    PkdRecvS,
    /// Unknown type (vendor extension).
    Unknown,
}

impl PacketKind {
    /// Classify a 16-byte type field.
    pub fn from_type(t: &[u8; 16]) -> Self {
        match t {
            b"PAR 2.0\0Main\0\0\0\0" => Self::Main,
            b"PAR 2.0\0FileDesc" => Self::FileDesc,
            b"PAR 2.0\0IFSC\0\0\0\0" => Self::Ifsc,
            b"PAR 2.0\0RecvSlic" => Self::RecvSlic,
            b"PAR 2.0\0Creator\0" => Self::Creator,
            b"PAR 2.0\0UniFileN" => Self::UniFileN,
            b"PAR 2.0\0CommASCI" => Self::CommAsci,
            b"PAR 2.0\0CommUni\0" => Self::CommUni,
            b"PAR 2.0\0FileSlic" => Self::FileSlic,
            b"PAR 2.0\0RFSC\0\0\0\0" => Self::Rfsc,
            b"PAR 2.0\0PkdMain\0" => Self::PkdMain,
            b"PAR 2.0\0PkdRecvS" => Self::PkdRecvS,
            _ => Self::Unknown,
        }
    }

    /// The 16-byte type field for a known kind (`None` for [`PacketKind::Unknown`]).
    pub fn type_bytes(self) -> Option<[u8; 16]> {
        Some(match self {
            Self::Main => *b"PAR 2.0\0Main\0\0\0\0",
            Self::FileDesc => *b"PAR 2.0\0FileDesc",
            Self::Ifsc => *b"PAR 2.0\0IFSC\0\0\0\0",
            Self::RecvSlic => *b"PAR 2.0\0RecvSlic",
            Self::Creator => *b"PAR 2.0\0Creator\0",
            Self::UniFileN => *b"PAR 2.0\0UniFileN",
            Self::CommAsci => *b"PAR 2.0\0CommASCI",
            Self::CommUni => *b"PAR 2.0\0CommUni\0",
            Self::FileSlic => *b"PAR 2.0\0FileSlic",
            Self::Rfsc => *b"PAR 2.0\0RFSC\0\0\0\0",
            Self::PkdMain => *b"PAR 2.0\0PkdMain\0",
            Self::PkdRecvS => *b"PAR 2.0\0PkdRecvS",
            Self::Unknown => return None,
        })
    }
}

/// Parity file formats this crate recognises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParFormat {
    /// PAR 1.0 (`PAR\0` magic, 96-byte header).
    Par1,
    /// PAR 2.0 (`PAR2\0PKT` packets).
    Par2,
    /// PAR 3.0 (`PAR3\0PKT` packets).
    Par3,
}

/// PAR1 file header (96 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Par1Header {
    /// Format version (`0x0001_0000` for 1.0).
    pub version: u32,
    /// Creating client id.
    pub client: u32,
    /// Control hash (MD5 of the header from the set hash on, plus the file list).
    pub control_hash: [u8; 16],
    /// Set hash.
    pub set_hash: [u8; 16],
    /// Volume number (0 = index `.par`).
    pub volume_number: u64,
    /// Number of files.
    pub num_files: u64,
    /// Offset of the file list.
    pub file_list_offset: u64,
    /// Length of the file list.
    pub file_list_size: u64,
    /// Offset of the recovery data.
    pub data_offset: u64,
    /// Length of the recovery data.
    pub data_size: u64,
}

/// Parse a PAR1 header at the start of `data`.
pub fn parse_par1_header(data: &[u8]) -> Option<Par1Header> {
    if array::<8>(data, 0)? != PAR1_MAGIC {
        return None;
    }
    Some(Par1Header {
        version: u32_le(data, 8)?,
        client: u32_le(data, 12)?,
        control_hash: array(data, 16)?,
        set_hash: array(data, 32)?,
        volume_number: u64_le(data, 48)?,
        num_files: u64_le(data, 56)?,
        file_list_offset: u64_le(data, 64)?,
        file_list_size: u64_le(data, 72)?,
        data_offset: u64_le(data, 80)?,
        data_size: u64_le(data, 88)?,
    })
}

/// PAR3 packet header (48 bytes; the 16-byte hash is the packet's BLAKE3-128).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Par3PacketHeader {
    /// Packet length including the header.
    pub length: u64,
    /// Packet hash.
    pub hash: [u8; 16],
    /// Input set id.
    pub input_set_id: [u8; 8],
    /// Packet type.
    pub packet_type: [u8; 8],
}

/// Parse a PAR3 packet header at `off`.
pub fn parse_par3_header(data: &[u8], off: usize) -> Option<Par3PacketHeader> {
    if array::<8>(data, off)? != PAR3_MAGIC {
        return None;
    }
    Some(Par3PacketHeader {
        length: u64_le(data, off.checked_add(8)?)?,
        hash: array(data, off.checked_add(16)?)?,
        input_set_id: array(data, off.checked_add(32)?)?,
        packet_type: array(data, off.checked_add(40)?)?,
    })
}

/// Detect the parity format of a buffer from its leading magic (searching the first 64 KiB
/// for a PAR2 / PAR3 packet magic so a leading yEnc artefact does not hide it).
pub fn detect_format(data: &[u8]) -> Option<ParFormat> {
    if data.starts_with(&PAR1_MAGIC) {
        return Some(ParFormat::Par1);
    }
    let head = data.get(..data.len().min(64 * 1024)).unwrap_or(data);
    let p2 = memchr::memmem::find(head, &PAR2_MAGIC);
    let p3 = memchr::memmem::find(head, &PAR3_MAGIC);
    match (p2, p3) {
        (Some(a), Some(b)) => Some(if a <= b {
            ParFormat::Par2
        } else {
            ParFormat::Par3
        }),
        (Some(_), None) => Some(ParFormat::Par2),
        (None, Some(_)) => Some(ParFormat::Par3),
        (None, None) => None,
    }
}

/// Which tool wrote a set, from its `Creator` packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreatorTool {
    /// `par2cmdline` (original or BlackIkeEagle fork).
    Par2Cmdline,
    /// `par2cmdline-turbo`.
    Par2CmdlineTurbo,
    /// QuickPar.
    QuickPar,
    /// MultiPar / par2j.
    MultiPar,
    /// ParPar.
    ParPar,
    /// nzbfast / parfast.
    Nzbfast,
    /// This crate (and its `nzbget-parity` predecessor).
    ParRs,
    /// Anything else.
    Other,
}

impl fmt::Display for CreatorTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Par2Cmdline => "par2cmdline",
            Self::Par2CmdlineTurbo => "par2cmdline-turbo",
            Self::QuickPar => "QuickPar",
            Self::MultiPar => "MultiPar",
            Self::ParPar => "ParPar",
            Self::Nzbfast => "nzbfast",
            Self::ParRs => "par-rs",
            Self::Other => "other",
        })
    }
}

/// Decoded `Creator` packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatorInfo {
    /// Set id from the packet header; `None` when built by [`CreatorInfo::parse`] alone.
    pub set_id: Option<[u8; 16]>,
    /// Raw client string (NUL padding removed, lossily decoded).
    pub raw: String,
    /// Classified tool.
    pub tool: CreatorTool,
    /// Version token (for example, `0.8.1`, `1.5.0`), if present.
    pub version: Option<String>,
    /// Architecture / platform token (for example, `x86_64`, `aarch64`, `win64`), if present.
    pub arch: Option<String>,
}

impl CreatorInfo {
    /// Classify a creator string.
    pub fn parse(raw: &[u8]) -> Self {
        let raw = String::from_utf8_lossy(trim_nul(raw)).into_owned();
        let lower = raw.to_ascii_lowercase();
        let tool = if lower.contains("turbo") {
            CreatorTool::Par2CmdlineTurbo
        } else if lower.contains("par2cmdline") || lower.contains("par2 cmdline") {
            CreatorTool::Par2Cmdline
        } else if lower.contains("quickpar") {
            CreatorTool::QuickPar
        } else if lower.contains("multipar") || lower.contains("par2j") {
            CreatorTool::MultiPar
        } else if lower.contains("parpar") {
            CreatorTool::ParPar
        } else if lower.contains("nzbfast") || lower.contains("parfast") {
            CreatorTool::Nzbfast
        } else if lower.contains("par-rs")
            || lower.contains("nzbget-parity")
            || lower.contains("par_rs")
        {
            CreatorTool::ParRs
        } else {
            CreatorTool::Other
        };
        let version = raw
            .split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')')
            .map(|t| t.trim_start_matches(['v', 'V']))
            .find(|t| {
                let mut dots = 0;
                !t.is_empty()
                    && t.chars().all(|c| {
                        if c == '.' {
                            dots += 1;
                        }
                        c.is_ascii_digit() || c == '.'
                    })
                    && dots >= 1
                    && t.chars().next().is_some_and(|c| c.is_ascii_digit())
            })
            .map(str::to_owned);
        let arch = [
            "x86_64", "amd64", "x64", "aarch64", "arm64", "armv7", "armhf", "i686", "x86", "win64",
            "win32", "linux", "darwin", "macos", "windows",
        ]
        .iter()
        .find(|a| {
            lower
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|t| t == **a)
        })
        .map(|a| (*a).to_owned());
        Self {
            set_id: None,
            raw,
            tool,
            version,
            arch,
        }
    }
}

/// Analysis of a PAR2 filename.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Par2FileName {
    /// Name without the `.par2` / `.volNNN+MM.par2` suffix.
    pub base: String,
    /// First recovery block number of a volume.
    pub first_block: Option<u32>,
    /// Block count of a `.volNNN+MM.par2` volume.
    pub block_count: Option<u32>,
    /// `true` for the index file (`name.par2`).
    pub is_index: bool,
}

/// Parse `name.par2`, `name.volNNN+MM.par2` or `name.volNNN-MMM.par2` (case-insensitive).
pub fn parse_par2_filename(name: &str) -> Option<Par2FileName> {
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".par2")?;
    let orig_stem = name.get(..stem.len())?;
    let Some(dot) = stem.rfind(".vol") else {
        return Some(Par2FileName {
            base: orig_stem.to_owned(),
            first_block: None,
            block_count: None,
            is_index: true,
        });
    };
    let seg = stem.get(dot.checked_add(4)?..)?;
    let base = orig_stem.get(..dot)?.to_owned();
    if let Some((a, b)) = seg.split_once('+') {
        let first = a.parse::<u32>().ok()?;
        let count = b.parse::<u32>().ok()?;
        return Some(Par2FileName {
            base,
            first_block: Some(first),
            block_count: Some(count),
            is_index: false,
        });
    }
    if let Some((a, b)) = seg.split_once('-') {
        let first = a.parse::<u32>().ok()?;
        let last = b.parse::<u32>().ok()?;
        let count = last.checked_sub(first)?.checked_add(1)?;
        return Some(Par2FileName {
            base,
            first_block: Some(first),
            block_count: Some(count),
            is_index: false,
        });
    }
    None
}

/// One packet located in the buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketInfo {
    /// Offset of the header.
    pub offset: usize,
    /// Declared packet length.
    pub length: u64,
    /// Recovery set id.
    pub set_id: [u8; 16],
    /// Packet type.
    pub kind: PacketKind,
    /// Raw type field (for [`PacketKind::Unknown`]).
    pub type_bytes: [u8; 16],
    /// `Some(result)` when the MD5 was checked.
    pub md5_ok: Option<bool>,
    /// Declared MD5.
    pub md5: [u8; 16],
}

/// Decoded `Main` or `PkdMain` packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MainInfo {
    /// Set id.
    pub set_id: [u8; 16],
    /// Slice size.
    pub slice_size: u64,
    /// Sub-slice size (packed main packets only).
    pub subslice_size: Option<u64>,
    /// File ids in the recovery set, in packet order.
    pub recovery_set: Vec<[u8; 16]>,
    /// File ids of non-recovery files.
    pub non_recovery_set: Vec<[u8; 16]>,
    /// The body was shorter than its file count claimed.
    pub truncated: bool,
    /// `MD5(body) == set_id`: `PAR2` derives the set id from the Main packet body, so when this
    /// holds the `recovery_set` and `non_recovery_set` lists are exactly the ones the set id was
    /// made from (nobody added a file to the set afterwards).
    pub body_hashes_to_set_id: bool,
}

/// Decoded `FileDesc` packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileDescInfo {
    /// Set id.
    pub set_id: [u8; 16],
    /// File id.
    pub file_id: [u8; 16],
    /// MD5 of the whole file.
    pub md5: [u8; 16],
    /// MD5 of the first 16 KiB.
    pub md5_16k: [u8; 16],
    /// File length.
    pub length: u64,
    /// Raw name bytes (NUL padding removed).
    pub name_raw: Vec<u8>,
    /// Name decoded (UTF-8, lossily) and sanitised: no control / ANSI escape characters, no
    /// path components.
    pub name: String,
}

/// Decoded `IFSC` packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfscInfo {
    /// Set id.
    pub set_id: [u8; 16],
    /// File id.
    pub file_id: [u8; 16],
    /// Per-slice `(md5, crc32)`.
    pub slices: Vec<([u8; 16], u32)>,
}

/// A recovery slice (`RecvSlic` or `PkdRecvS`) located in the buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverySliceInfo {
    /// Set id.
    pub set_id: [u8; 16],
    /// Exponent.
    pub exponent: u32,
    /// Offset of the slice data.
    pub data_offset: usize,
    /// Declared data length.
    pub data_len: u64,
    /// How many data bytes are actually present in the buffer.
    pub available: usize,
    /// Packed variant.
    pub packed: bool,
    /// MD5 of the first [`EXP0_PREFIX_LEN`] bytes of an exponent-0 slice (the XOR of all input
    /// slices, a set fingerprint independent of the recovery count).
    pub exp0_prefix_md5: Option<[u8; 16]>,
}

/// Decoded `UniFileN` packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnicodeNameInfo {
    /// Set id.
    pub set_id: [u8; 16],
    /// File id.
    pub file_id: [u8; 16],
    /// Decoded (and sanitised) name.
    pub name: String,
}

/// Decoded comment packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommentInfo {
    /// Set id.
    pub set_id: [u8; 16],
    /// Comment text (lossily decoded).
    pub text: String,
    /// Unicode variant.
    pub unicode: bool,
}

/// Decoded `FileSlic` packet (input slice stored in the set).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileSliceInfo {
    /// Set id.
    pub set_id: [u8; 16],
    /// File id.
    pub file_id: [u8; 16],
    /// Slice index within the file.
    pub slice_index: u64,
    /// Offset of the slice data.
    pub data_offset: usize,
    /// Declared data length.
    pub data_len: u64,
}

/// Decoded `RFSC` packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryChecksumInfo {
    /// Set id.
    pub set_id: [u8; 16],
    /// Per-recovery-slice `(md5, crc32)`.
    pub slices: Vec<([u8; 16], u32)>,
}

/// Everything found in a buffer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Par2Inspection {
    /// Detected format of the buffer head (`None` for no recognisable magic).
    pub format: Option<ParFormat>,
    /// Every packet with a shaped header, in buffer order.
    pub packets: Vec<PacketInfo>,
    /// `Main` / `PkdMain` packets.
    pub main: Vec<MainInfo>,
    /// `FileDesc` packets.
    pub files: Vec<FileDescInfo>,
    /// `IFSC` packets.
    pub ifsc: Vec<IfscInfo>,
    /// Recovery slices.
    pub recovery: Vec<RecoverySliceInfo>,
    /// Creator packets.
    pub creators: Vec<CreatorInfo>,
    /// Unicode file names.
    pub unicode_names: Vec<UnicodeNameInfo>,
    /// Comments.
    pub comments: Vec<CommentInfo>,
    /// Stored input slices.
    pub file_slices: Vec<FileSliceInfo>,
    /// Recovery file slice checksums.
    pub recovery_checksums: Vec<RecoveryChecksumInfo>,
    /// PAR1 header when the buffer is a PAR1 file.
    pub par1: Option<Par1Header>,
    /// PAR3 packet headers found (PAR3 bodies are not decoded).
    pub par3: Vec<Par3PacketHeader>,
    /// A packet claimed more bytes than the buffer holds.
    pub truncated: bool,
    /// Number of times the scanner had to search forward for the next magic.
    pub resyncs: usize,
    /// Packets whose MD5 did not verify (when verification was requested).
    pub bad_md5: usize,
}

/// A valid-looking header: length `>= 64`, a multiple of 4, and not past the end of
/// `u64::MAX`.
fn shaped(length: u64) -> bool {
    length >= HEADER_LEN as u64 && length.is_multiple_of(4)
}

/// Decode a PAR2 name: `UTF-8` (lossily) with control characters, ANSI escape sequences, and
/// path components removed. An empty result becomes `"_"`.
pub fn sanitize_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(trim_nul(raw));
    // Drop `ESC [ ... <final byte>` sequences, then every other control character.
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&d) {
                        break;
                    }
                }
            }
            continue;
        }
        if c.is_control() {
            continue;
        }
        out.push(c);
    }
    // Keep only the final path component; `..` components vanish with the rest.
    let last = out.rsplit(['/', '\\']).next().unwrap_or("").trim();
    let last = last.trim_start_matches('.').trim();
    if last.is_empty() {
        "_".to_owned()
    } else {
        last.to_owned()
    }
}

/// Decode UTF-16LE (lossily) and sanitise like [`sanitize_name`].
pub fn sanitize_utf16le_name(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let s: String = char::decode_utf16(units.iter().copied())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    let trimmed = s.trim_end_matches('\0');
    sanitize_name(trimmed.as_bytes())
}

fn parse_main(set_id: [u8; 16], body: &[u8], packed: bool) -> Option<MainInfo> {
    let mut off = 0usize;
    let subslice_size = if packed {
        let v = u64_le(body, off)?;
        off = off.checked_add(8)?;
        Some(v)
    } else {
        None
    };
    let slice_size = u64_le(body, off)?;
    off = off.checked_add(8)?;
    let count = u32_le(body, off)? as usize;
    off = off.checked_add(4)?;
    let mut recovery_set = Vec::with_capacity(count.min(body.len() / 16));
    let mut truncated = false;
    for _ in 0..count {
        match array::<16>(body, off) {
            Some(id) => {
                recovery_set.push(id);
                off = off.checked_add(16)?;
            }
            None => {
                truncated = true;
                break;
            }
        }
    }
    let mut non_recovery_set = Vec::new();
    if !truncated {
        while let Some(id) = array::<16>(body, off) {
            non_recovery_set.push(id);
            off = off.checked_add(16)?;
        }
    }
    let body_hashes_to_set_id = <[u8; 16]>::from(Md5::digest(body)) == set_id;
    Some(MainInfo {
        set_id,
        slice_size,
        subslice_size,
        recovery_set,
        non_recovery_set,
        truncated,
        body_hashes_to_set_id,
    })
}

fn parse_file_desc(set_id: [u8; 16], body: &[u8]) -> Option<FileDescInfo> {
    let file_id = array::<16>(body, 0)?;
    let md5 = array::<16>(body, 16)?;
    let md5_16k = array::<16>(body, 32)?;
    let length = u64_le(body, 48)?;
    let name_raw = trim_nul(body.get(56..)?).to_vec();
    let name = sanitize_name(&name_raw);
    Some(FileDescInfo {
        set_id,
        file_id,
        md5,
        md5_16k,
        length,
        name_raw,
        name,
    })
}

fn parse_checksum_pairs(body: &[u8]) -> Vec<([u8; 16], u32)> {
    body.as_chunks::<20>()
        .0
        .iter()
        .filter_map(|c| {
            let md5: [u8; 16] = c.get(..16)?.try_into().ok()?;
            let crc = u32_le(c, 16)?;
            Some((md5, crc))
        })
        .collect()
}

/// Which packets get their MD5 checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyMode {
    /// Trust every header (fastest; a corrupt body is decoded as is).
    None,
    /// Verify every packet except the bulk ones (`RecvSlic`, `PkdRecvS`, `FileSlic`): metadata
    /// is cheap to hash and a corrupt description must not be believed.
    Metadata,
    /// Verify everything, recovery data included (one pass over the whole buffer).
    All,
}

/// Inspect a PAR2 buffer. With `verify_packet_md5` every packet whose body is fully present has
/// its MD5 checked (recovery slices included, which costs one pass over their data).
pub fn inspect_par2(data: &[u8], verify_packet_md5: bool) -> Par2Inspection {
    inspect_par2_with(
        data,
        if verify_packet_md5 {
            VerifyMode::All
        } else {
            VerifyMode::None
        },
    )
}

/// [`inspect_par2`] with a choice of which packets to verify.
///
/// A packet whose MD5 fails, or whose type is unknown and unverified, is not trusted for its
/// declared length either: the scanner resynchronises right after its magic, so a garbage header
/// cannot swallow the real packet that follows it.
pub fn inspect_par2_with(data: &[u8], verify: VerifyMode) -> Par2Inspection {
    let mut r = Par2Inspection {
        format: detect_format(data),
        ..Par2Inspection::default()
    };
    if let Some(h) = parse_par1_header(data) {
        r.par1 = Some(h);
        return r;
    }
    let finder = memchr::memmem::Finder::new(&PAR2_MAGIC);
    let finder3 = memchr::memmem::Finder::new(&PAR3_MAGIC);
    let mut pos = 0usize;
    let mut expect_contiguous = false;
    while pos < data.len() {
        let rest = match data.get(pos..) {
            Some(x) => x,
            None => break,
        };
        // Next PAR2 magic (and any PAR3 headers passed on the way).
        let Some(rel) = finder.find(rest) else {
            // No more PAR2 packets; still record PAR3 headers in the remainder.
            let mut scan = 0usize;
            while let Some(p3) = finder3.find(rest.get(scan..).unwrap_or(&[])) {
                let at = scan.saturating_add(p3);
                if let Some(h) = parse_par3_header(rest, at) {
                    r.par3.push(h);
                }
                scan = at.saturating_add(8);
            }
            break;
        };
        if rel != 0 {
            if expect_contiguous {
                r.resyncs = r.resyncs.saturating_add(1);
            }
            let skipped = rest.get(..rel).unwrap_or(&[]);
            let mut scan = 0usize;
            while let Some(p3) = finder3.find(skipped.get(scan..).unwrap_or(&[])) {
                let at = scan.saturating_add(p3);
                if let Some(h) = parse_par3_header(skipped, at) {
                    r.par3.push(h);
                }
                scan = at.saturating_add(8);
            }
        }
        let off = pos.saturating_add(rel);
        expect_contiguous = true;
        let Some(length) = u64_le(data, off.saturating_add(8)) else {
            r.truncated = true;
            break;
        };
        let Some(md5) = array::<16>(data, off.saturating_add(16)) else {
            r.truncated = true;
            break;
        };
        let Some(set_id) = array::<16>(data, off.saturating_add(32)) else {
            r.truncated = true;
            break;
        };
        let Some(type_bytes) = array::<16>(data, off.saturating_add(48)) else {
            r.truncated = true;
            break;
        };
        if !shaped(length) {
            // Corrupt header: resynchronize after the magic.
            pos = off.saturating_add(8);
            continue;
        }
        let kind = PacketKind::from_type(&type_bytes);
        let body_off = off.saturating_add(HEADER_LEN);
        let body_len_u64 = length - HEADER_LEN as u64;
        let available_body = data
            .len()
            .saturating_sub(body_off)
            .min(usize::try_from(body_len_u64).unwrap_or(usize::MAX));
        let complete = available_body as u64 == body_len_u64;
        if !complete {
            r.truncated = true;
        }
        let body = take(data, body_off, available_body).unwrap_or(&[]);
        let bulk = matches!(
            kind,
            PacketKind::RecvSlic | PacketKind::PkdRecvS | PacketKind::FileSlic
        );
        let check = match verify {
            VerifyMode::None => false,
            VerifyMode::Metadata => !bulk,
            VerifyMode::All => true,
        };
        let md5_ok = if check && complete {
            let mut ctx = Md5::new();
            ctx.update(set_id);
            ctx.update(type_bytes);
            ctx.update(body);
            let got: [u8; 16] = ctx.finalize().into();
            if got != md5 {
                r.bad_md5 = r.bad_md5.saturating_add(1);
            }
            Some(got == md5)
        } else {
            None
        };
        r.packets.push(PacketInfo {
            offset: off,
            length,
            set_id,
            kind,
            type_bytes,
            md5_ok,
            md5,
        });
        // A failed MD5, or an unknown type that could not be verified, means the header itself
        // may be garbage: do not skip its declared length, look for the next magic instead.
        if md5_ok == Some(false) || (kind == PacketKind::Unknown && md5_ok != Some(true)) {
            pos = off.saturating_add(8);
            continue;
        }
        if complete {
            match kind {
                PacketKind::Main | PacketKind::PkdMain => {
                    if let Some(m) = parse_main(set_id, body, kind == PacketKind::PkdMain) {
                        r.main.push(m);
                    }
                }
                PacketKind::FileDesc => {
                    if complete && let Some(f) = parse_file_desc(set_id, body) {
                        r.files.push(f);
                    }
                }
                PacketKind::Ifsc => {
                    if let Some(file_id) = array::<16>(body, 0) {
                        let slices = parse_checksum_pairs(body.get(16..).unwrap_or(&[]));
                        r.ifsc.push(IfscInfo {
                            set_id,
                            file_id,
                            slices,
                        });
                    }
                }
                PacketKind::RecvSlic | PacketKind::PkdRecvS => {
                    if let Some(exponent) = u32_le(body, 0) {
                        let payload = body.get(4..).unwrap_or(&[]);
                        let exp0_prefix_md5 = (exponent == 0 && !payload.is_empty()).then(|| {
                            let head = payload
                                .get(..payload.len().min(EXP0_PREFIX_LEN))
                                .unwrap_or(payload);
                            Md5::digest(head).into()
                        });
                        r.recovery.push(RecoverySliceInfo {
                            set_id,
                            exponent,
                            data_offset: body_off.saturating_add(4),
                            data_len: body_len_u64.saturating_sub(4),
                            available: payload.len(),
                            packed: kind == PacketKind::PkdRecvS,
                            exp0_prefix_md5,
                        });
                    }
                }
                PacketKind::Creator => r.creators.push(CreatorInfo {
                    set_id: Some(set_id),
                    ..CreatorInfo::parse(body)
                }),
                PacketKind::UniFileN => {
                    if let Some(file_id) = array::<16>(body, 0) {
                        r.unicode_names.push(UnicodeNameInfo {
                            set_id,
                            file_id,
                            name: sanitize_utf16le_name(body.get(16..).unwrap_or(&[])),
                        });
                    }
                }
                PacketKind::CommAsci => {
                    r.comments.push(CommentInfo {
                        set_id,
                        text: String::from_utf8_lossy(trim_nul(body)).into_owned(),
                        unicode: false,
                    });
                }
                PacketKind::CommUni => {
                    // 16 bytes: `MD5` of the ASCII comment packet, then UTF-16LE text.
                    let text_bytes = body.get(16..).unwrap_or(&[]);
                    let units: Vec<u16> = text_bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_le_bytes(*c))
                        .collect();
                    let text: String = char::decode_utf16(units)
                        .map(|x| x.unwrap_or(char::REPLACEMENT_CHARACTER))
                        .collect();
                    r.comments.push(CommentInfo {
                        set_id,
                        text: text.trim_end_matches('\0').to_owned(),
                        unicode: true,
                    });
                }
                PacketKind::FileSlic => {
                    if let (Some(file_id), Some(slice_index)) =
                        (array::<16>(body, 0), u64_le(body, 16))
                    {
                        r.file_slices.push(FileSliceInfo {
                            set_id,
                            file_id,
                            slice_index,
                            data_offset: body_off.saturating_add(24),
                            data_len: body_len_u64.saturating_sub(24),
                        });
                    }
                }
                PacketKind::Rfsc => r.recovery_checksums.push(RecoveryChecksumInfo {
                    set_id,
                    slices: parse_checksum_pairs(body),
                }),
                PacketKind::Unknown => {}
            }
        }
        if !complete {
            break;
        }
        pos = match usize::try_from(length)
            .ok()
            .and_then(|l| off.checked_add(l))
        {
            Some(p) => p,
            None => break,
        };
    }
    r
}

/// The packets an inventory needs, scanned in one optimistic pass: lengths are trusted while
/// walking, every metadata packet's MD5 is checked afterwards in one 16-lane batch
/// ([`crate::md5simd::md5_many`]), and recovery data is neither hashed nor decoded. Returns
/// `None` the moment a packet fails its MD5, an unknown type cannot be verified, or an unknown
/// packet is cut short: those are exactly the cases where [`inspect_par2_with`] resynchronises
/// and must be used instead. When it returns `Some`, the result's `main`, `files`, `ifsc`,
/// `unicode_names`, `creators` and `truncated` fields equal those of
/// `inspect_par2_with(data, VerifyMode::Metadata)`; the other fields are left empty.
pub(crate) fn inspect_for_inventory(data: &[u8]) -> Option<Par2Inspection> {
    if parse_par1_header(data).is_some() {
        return None;
    }
    let mut r = Par2Inspection {
        format: detect_format(data),
        ..Par2Inspection::default()
    };
    let finder = memchr::memmem::Finder::new(&PAR2_MAGIC);
    let mut msgs: Vec<&[u8]> = Vec::new();
    let mut expected: Vec<[u8; 16]> = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let rest = data.get(pos..)?;
        let Some(rel) = finder.find(rest) else { break };
        let off = pos.saturating_add(rel);
        let (Some(length), Some(md5), Some(set_id), Some(type_bytes)) = (
            u64_le(data, off.saturating_add(8)),
            array::<16>(data, off.saturating_add(16)),
            array::<16>(data, off.saturating_add(32)),
            array::<16>(data, off.saturating_add(48)),
        ) else {
            r.truncated = true;
            break;
        };
        if !shaped(length) {
            pos = off.saturating_add(8);
            continue;
        }
        let kind = PacketKind::from_type(&type_bytes);
        let body_off = off.saturating_add(HEADER_LEN);
        let body_len_u64 = length - HEADER_LEN as u64;
        let available_body = data
            .len()
            .saturating_sub(body_off)
            .min(usize::try_from(body_len_u64).unwrap_or(usize::MAX));
        let complete = available_body as u64 == body_len_u64;
        if !complete {
            if kind == PacketKind::Unknown {
                return None; // the full scanner resynchronises here
            }
            r.truncated = true;
            break;
        }
        let body = take(data, body_off, available_body).unwrap_or(&[]);
        let bulk = matches!(
            kind,
            PacketKind::RecvSlic | PacketKind::PkdRecvS | PacketKind::FileSlic
        );
        if !bulk {
            // set id ‖ type ‖ body is contiguous in the buffer: hash it in place later.
            msgs.push(
                take(
                    data,
                    off.saturating_add(32),
                    available_body.saturating_add(32),
                )
                .unwrap_or(&[]),
            );
            expected.push(md5);
        }
        match kind {
            PacketKind::Main | PacketKind::PkdMain => {
                if let Some(m) = parse_main(set_id, body, kind == PacketKind::PkdMain) {
                    r.main.push(m);
                }
            }
            PacketKind::FileDesc => {
                if let Some(f) = parse_file_desc(set_id, body) {
                    r.files.push(f);
                }
            }
            PacketKind::Ifsc => {
                if let Some(file_id) = array::<16>(body, 0) {
                    r.ifsc.push(IfscInfo {
                        set_id,
                        file_id,
                        slices: parse_checksum_pairs(body.get(16..).unwrap_or(&[])),
                    });
                }
            }
            PacketKind::UniFileN => {
                if let Some(file_id) = array::<16>(body, 0) {
                    r.unicode_names.push(UnicodeNameInfo {
                        set_id,
                        file_id,
                        name: sanitize_utf16le_name(body.get(16..).unwrap_or(&[])),
                    });
                }
            }
            PacketKind::Creator => r.creators.push(CreatorInfo {
                set_id: Some(set_id),
                ..CreatorInfo::parse(body)
            }),
            _ => {}
        }
        pos = usize::try_from(length)
            .ok()
            .and_then(|l| off.checked_add(l))?;
    }
    if !msgs.is_empty() {
        let got = crate::md5simd::md5_many(&msgs);
        if got.len() != expected.len() || got.iter().zip(&expected).any(|(g, e)| g != e) {
            return None;
        }
    }
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creator_fingerprints() {
        let c = CreatorInfo::parse(b"Created by par2cmdline-turbo version 1.1.1 (x86_64)\0\0");
        assert_eq!(c.tool, CreatorTool::Par2CmdlineTurbo);
        assert_eq!(c.version.as_deref(), Some("1.1.1"));
        assert_eq!(c.arch.as_deref(), Some("x86_64"));
        assert_eq!(
            CreatorInfo::parse(b"Created by par2cmdline version 0.8.1.").tool,
            CreatorTool::Par2Cmdline
        );
        assert_eq!(
            CreatorInfo::parse(b"QuickPar 0.9").tool,
            CreatorTool::QuickPar
        );
        assert_eq!(
            CreatorInfo::parse(b"MultiPar v1.3.2.6 (par2j64)").tool,
            CreatorTool::MultiPar
        );
        assert_eq!(
            CreatorInfo::parse(b"ParPar v0.4.6 [https://animetosho.org/app/parpar]").tool,
            CreatorTool::ParPar
        );
        assert_eq!(
            CreatorInfo::parse(b"nzbfast parfast 1.9.0").tool,
            CreatorTool::Nzbfast
        );
        assert_eq!(CreatorInfo::parse(b"par-rs 0.2.0").tool, CreatorTool::ParRs);
        let o = CreatorInfo::parse(b"something else");
        assert_eq!(o.tool, CreatorTool::Other);
        assert_eq!(o.version, None);
        assert_eq!(CreatorTool::ParPar.to_string(), "ParPar");
        assert_eq!(
            CreatorInfo::parse(b"MyTool aarch64 linux").arch.as_deref(),
            Some("aarch64")
        );
    }

    #[test]
    fn filename_analysis() {
        let v = parse_par2_filename("Release.vol007+08.PAR2").unwrap();
        assert_eq!(v.base, "Release");
        assert_eq!(
            (v.first_block, v.block_count, v.is_index),
            (Some(7), Some(8), false)
        );
        let i = parse_par2_filename("a.b.par2").unwrap();
        assert_eq!((i.base.as_str(), i.is_index), ("a.b", true));
        let r = parse_par2_filename("x.vol10-19.par2").unwrap();
        assert_eq!((r.first_block, r.block_count), (Some(10), Some(10)));
        assert!(parse_par2_filename("x.volabc.par2").is_none());
        assert!(parse_par2_filename("x.rar").is_none());
        assert!(parse_par2_filename("x.vol5-2.par2").is_none());
    }

    #[test]
    fn name_sanitising() {
        assert_eq!(sanitize_name(b"../../etc/passwd"), "passwd");
        assert_eq!(sanitize_name(b"dir\\sub\\file.rar\0\0"), "file.rar");
        assert_eq!(sanitize_name(b"\x1b[31mred\x1b[0m.bin"), "red.bin");
        assert_eq!(sanitize_name(b"\x07bell\ttab"), "belltab");
        assert_eq!(sanitize_name(b"/"), "_");
        assert_eq!(sanitize_name(b""), "_");
        assert_eq!(sanitize_name(b"...hidden"), "hidden");
        let utf16: Vec<u8> = "pâr\u{1f600}.rar"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(sanitize_utf16le_name(&utf16), "pâr\u{1f600}.rar");
        assert_eq!(sanitize_utf16le_name(&utf16[..3]), "p");
    }

    #[test]
    fn par1_and_par3_headers() {
        let mut p1 = Vec::new();
        p1.extend_from_slice(&PAR1_MAGIC);
        p1.extend_from_slice(&0x0001_0000u32.to_le_bytes());
        p1.extend_from_slice(&7u32.to_le_bytes());
        p1.extend_from_slice(&[1u8; 16]);
        p1.extend_from_slice(&[2u8; 16]);
        for v in [3u64, 4, 5, 6, 7, 8] {
            p1.extend_from_slice(&v.to_le_bytes());
        }
        let h = parse_par1_header(&p1).unwrap();
        assert_eq!(
            (
                h.version,
                h.client,
                h.volume_number,
                h.num_files,
                h.data_size
            ),
            (0x0001_0000, 7, 3, 4, 8)
        );
        assert!(parse_par1_header(&p1[..90]).is_none());
        assert_eq!(detect_format(&p1), Some(ParFormat::Par1));
        let r = inspect_par2(&p1, true);
        assert_eq!(r.par1, Some(h));
        assert!(r.packets.is_empty());

        let mut p3 = vec![0u8; 5];
        p3.extend_from_slice(&PAR3_MAGIC);
        p3.extend_from_slice(&100u64.to_le_bytes());
        p3.extend_from_slice(&[9u8; 16]);
        p3.extend_from_slice(&[8u8; 8]);
        p3.extend_from_slice(b"PAR 3.0\0");
        assert_eq!(detect_format(&p3), Some(ParFormat::Par3));
        let r = inspect_par2(&p3, false);
        assert_eq!(r.par3.len(), 1);
        assert_eq!(r.par3[0].length, 100);
        assert_eq!(r.par3[0].packet_type, *b"PAR 3.0\0");
        assert!(parse_par3_header(&p3, 5).is_some());
        assert!(parse_par3_header(&p3, 6).is_none());
        assert_eq!(detect_format(b"nothing here"), None);
    }

    #[test]
    fn packet_kinds_round_trip() {
        for k in [
            PacketKind::Main,
            PacketKind::FileDesc,
            PacketKind::Ifsc,
            PacketKind::RecvSlic,
            PacketKind::Creator,
            PacketKind::UniFileN,
            PacketKind::CommAsci,
            PacketKind::CommUni,
            PacketKind::FileSlic,
            PacketKind::Rfsc,
            PacketKind::PkdMain,
            PacketKind::PkdRecvS,
        ] {
            assert_eq!(PacketKind::from_type(&k.type_bytes().unwrap()), k);
        }
        assert_eq!(PacketKind::Unknown.type_bytes(), None);
        assert_eq!(
            PacketKind::from_type(b"PAR 2.0\0Vendor\0\0"),
            PacketKind::Unknown
        );
    }
}
