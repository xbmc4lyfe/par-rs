//! Minimal command-line front end, mainly for manual testing and for differential checks
//! against `par2cmdline`.
//!
//! ```text
//! par-rs create [-s slice_size] [-r recovery_blocks] [-n volumes|exp|single] <base.par2> <files...>
//! par-rs verify [--extra <dir>] <file.par2>
//! par-rs repair [--extra <dir>] [--threads N] [--mem MiB] [--full-md5] [--sync] <file.par2>
//! par-rs rename [--dry-run] <dir>
//! par-rs info <file.par2>
//! ```

use par_rs::create::{create, CreateOptions, SourceFile, VolumeScheme};
use par_rs::renamer::{ParRenamer, RenamerEvent, RenamerOptions};
use par_rs::repairer::{Level, Par2Repairer, RepairObserver, RepairOptions, RepairResult, SourceFileState, Stage};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

struct Console {
    verbose: bool,
    t0: std::time::Instant,
}

impl RepairObserver for Console {
    fn stage(&mut self, stage: Stage) {
        eprintln!("== {stage:?} (t+{:.3}s)", self.t0.elapsed().as_secs_f64());
    }
    fn file_verified(&mut self, f: &SourceFileState) {
        eprintln!("   {:<40} {:?} ({}/{} blocks)", f.target_filename, f.status, f.available_blocks, f.block_count);
    }
    fn message(&mut self, level: Level, text: &str) {
        if self.verbose || level != Level::Detail {
            eprintln!("   [{level:?}] {text}");
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: par-rs create [-s slice] [-r blocks] [-n N|exp|single] <base> <files...>");
    eprintln!("       par-rs verify [--extra dir] [--threads N] [--full-md5] <file.par2>");
    eprintln!("       par-rs repair [--extra dir] [--threads N] [--mem MiB] [--no-verify] [--full-md5] [--sync] <file.par2>");
    eprintln!("       par-rs rename [--dry-run] <dir>");
    eprintln!("       par-rs info <file.par2>");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        return usage();
    };
    match cmd.as_str() {
        "create" => cmd_create(&args[1..]),
        "verify" | "repair" => cmd_repair(&args[1..], cmd == "repair"),
        "rename" => cmd_rename(&args[1..]),
        "info" => cmd_info(&args[1..]),
        _ => usage(),
    }
}

fn cmd_create(args: &[String]) -> ExitCode {
    let mut opts = CreateOptions::default();
    let mut rest: Vec<&String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-s" => {
                i += 1;
                opts.slice_size = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            "-r" => {
                i += 1;
                opts.recovery_blocks = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            "-n" => {
                i += 1;
                opts.volumes = match args.get(i).map(|s| s.as_str()) {
                    Some("exp") | None => VolumeScheme::Exponential,
                    Some("single") => VolumeScheme::Single,
                    Some(n) => VolumeScheme::Uniform(n.parse().unwrap_or(1)),
                };
            }
            _ => rest.push(&args[i]),
        }
        i += 1;
    }
    if rest.len() < 2 {
        return usage();
    }
    let base_path = PathBuf::from(rest[0]);
    let out_dir = base_path.parent().filter(|p| !p.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let base = base_path.file_name().map(|n| n.to_string_lossy().trim_end_matches(".par2").to_string()).unwrap_or_default();
    let sources: Vec<SourceFile> = rest[1..].iter().map(|p| SourceFile::new(PathBuf::from(p))).collect();
    let t = std::time::Instant::now();
    match create(&sources, &out_dir, &base, &opts, None, &mut |_, _, _| {}) {
        Ok(rep) => {
            eprintln!("created set {} with {} input blocks and {} recovery blocks in {:.2}s", rep.set_id, rep.input_slices, rep.recovery_slices, t.elapsed().as_secs_f64());
            for f in rep.files {
                eprintln!("   {}", f.display());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_repair(args: &[String], do_repair: bool) -> ExitCode {
    let mut extra: Vec<PathBuf> = Vec::new();
    let mut opts = RepairOptions::default();
    let mut target: Option<PathBuf> = None;
    let mut verbose = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--extra" => {
                i += 1;
                if let Some(d) = args.get(i) {
                    extra.push(PathBuf::from(d));
                }
            }
            "--threads" => {
                i += 1;
                opts.num_threads = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            "--mem" => {
                i += 1;
                opts.mem_limit_bytes = args.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(256) << 20;
            }
            "--no-verify" => opts.verify_repaired = false,
            "--full-md5" => opts.full_file_md5 = true,
            "--sync" => opts.sync_repaired = true,
            "-v" => verbose = true,
            other => target = Some(PathBuf::from(other)),
        }
        i += 1;
    }
    let Some(par) = target else {
        return usage();
    };
    let dir = par.parent().filter(|p| !p.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let mut obs = Console { verbose, t0: std::time::Instant::now() };
    let mut r = Par2Repairer::new(&dir, opts);
    let t = std::time::Instant::now();
    let loaded = match r.load_par2_set(&par) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("loaded {} par2 file(s), {} recovery blocks, block size {}", loaded.len(), r.recovery_blocks(), r.block_size());
    if let Err(e) = r.finalize() {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    let v = match r.verify(None, &mut obs) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("verified in {:.2}s: missing {} block(s), {} recovery block(s) available", t.elapsed().as_secs_f64(), v.missing_blocks, v.recovery_blocks);
    for d in &extra {
        match r.add_split_fragments(d, &mut obs).and_then(|a| r.add_extra_files_from_dir(d, &mut obs).map(|b| a + b)) {
            Ok(n) => eprintln!("extra files in {} supplied {n} block(s)", d.display()),
            Err(e) => eprintln!("error scanning {}: {e}", d.display()),
        }
    }
    if !do_repair {
        if r.verify_result().all_complete {
            eprintln!("All files are correct.");
            return ExitCode::SUCCESS;
        }
        eprintln!("Repair {}.", if r.repair_possible() { "is possible" } else { "is NOT possible" });
        return ExitCode::FAILURE;
    }
    let t = std::time::Instant::now();
    match r.repair(&mut obs) {
        Ok(RepairResult::NotNeeded) => {
            eprintln!("Repair not needed.");
            ExitCode::SUCCESS
        }
        Ok(RepairResult::Repaired { files, blocks_recovered, leftovers }) => {
            for l in &leftovers {
                eprintln!("   leftover: {}", l.display());
            }
            eprintln!("Repaired {} file(s), {blocks_recovered} block(s) reconstructed in {:.2}s", files.len(), t.elapsed().as_secs_f64());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_rename(args: &[String]) -> ExitCode {
    let dry = args.iter().any(|a| a == "--dry-run");
    let Some(dir) = args.iter().find(|a| !a.starts_with("--")) else {
        return usage();
    };
    let opts = RenamerOptions { detect_missing: true, dry_run: dry, ..Default::default() };
    match ParRenamer::new(PathBuf::from(dir), opts).run(None, &mut |e| match e {
        RenamerEvent::Progress(_, _) => {}
        other => eprintln!("   {other:?}"),
    }) {
        Ok(rep) => {
            eprintln!("{} file(s) renamed, {} missing", rep.renamed_count(), rep.missing.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_info(args: &[String]) -> ExitCode {
    let Some(p) = args.first() else {
        return usage();
    };
    match par_rs::packet::load_par2_file(Path::new(p), par_rs::packet::ScanOptions::FULL) {
        Ok(set) => {
            println!("set id:      {}", set.set_id.map(|s| s.to_string()).unwrap_or_default());
            println!("slice size:  {}", set.slice_size().unwrap_or(0));
            println!("creator:     {}", set.creator_string());
            println!("files:       {}", set.file_descs.len());
            for fd in set.file_descs.values() {
                println!("   {:<40} {:>12} bytes  {} slices", fd.local_name(), fd.file_length, set.ifscs.get(&fd.file_id).map(|i| i.slice_count()).unwrap_or(0));
            }
            println!("recovery:    {} slice(s): {:?}", set.recovery.len(), set.recovery.keys().collect::<Vec<_>>());
            println!("stats:       {:?}", set.stats);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
