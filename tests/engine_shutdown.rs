use par_rs::Kernel;
use par_rs::gf16::input_constant_logs;
use par_rs::reed_solomon::{Engine, EngineConfig, InputKind, InputReader, InputSpec, RsError};
use std::cell::RefCell;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const CHILD_CASE: &str = "PAR_RS_ENGINE_SHUTDOWN_CASE";

fn child(case: &str) {
    let mut process = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "engine_shutdown_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_CASE, case)
        // Bound captured diagnostics for the intentional unwind case.
        .env("RUST_BACKTRACE", "0")
        .env("RUST_LIB_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if process.try_wait().unwrap().is_some() {
            let output = process.wait_with_output().unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "{case}: {stderr}\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(
                stderr.contains("MARK_ENGINE_RETURN"),
                "child did not reach the engine result: {stderr}"
            );
            assert!(
                stderr.contains("MARK_RESOURCE_RETIRED"),
                "child did not retire its reader resource: {stderr}"
            );
            if matches!(case, "cancel" | "panic") {
                assert!(stderr.contains("MARK_QUEUE_FULL"), "{case}: {stderr}");
                assert!(
                    stderr.contains("MARK_FOURTH_READ_RELEASED"),
                    "{case}: {stderr}"
                );
            } else if case == "multi-error" {
                assert!(stderr.contains("MARK_ERROR_NEXT_QUEUE_FULL"), "{stderr}");
            }
            eprintln!("completed child {case}:\n{stderr}");
            return;
        }
        if Instant::now() >= deadline {
            let killed = process.kill();
            let output = process.wait_with_output().unwrap();
            panic!(
                "owned child {case} exceeded 20-second containment; kill={killed:?}\n{}\n{}",
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            );
        }
        // Parent containment polling only; child queue synchronization uses gates.
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn full_queue_cancellation_returns_and_retires_readers() {
    child("cancel");
}

#[test]
fn full_queue_read_error_returns_and_retires_other_readers() {
    child("multi-error");
}

#[test]
fn full_queue_consumer_unwind_retires_readers() {
    child("panic");
}

#[test]
fn normal_outputs_and_existing_error_controls_are_preserved() {
    for case in ["drain", "pre-cancel", "single-error", "multi-drain"] {
        child(case);
    }
}

struct ReadActivity(Arc<AtomicUsize>);
impl ReadActivity {
    fn begin(resource: &Arc<AtomicUsize>) -> Self {
        resource.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(resource))
    }
}
impl Drop for ReadActivity {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct SingleState {
    fourth_read: bool,
    release: bool,
}
struct SingleReader {
    state: Mutex<SingleState>,
    changed: Condvar,
    resource: Arc<AtomicUsize>,
    gated: bool,
    read_error: bool,
    calls: AtomicUsize,
}
impl InputReader for SingleReader {
    fn read_input(&self, source: usize, _offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        let _activity = ReadActivity::begin(&self.resource);
        self.calls.fetch_add(1, Ordering::SeqCst);
        if source == 3 && self.gated {
            let mut state = self.state.lock().unwrap();
            state.fourth_read = true;
            eprintln!("MARK_FOURTH_READ_ENTERED");
            self.changed.notify_all();
            while !state.release {
                state = self.changed.wait(state).unwrap();
            }
            drop(state);
            eprintln!("MARK_FOURTH_READ_RELEASED");
            if self.read_error {
                return Err(io::Error::other("owned single-reader failure"));
            }
        }
        bytes.fill(source as u8 + 1);
        Ok(())
    }
}

fn inputs(count: usize) -> Vec<InputSpec> {
    input_constant_logs(count)
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(source, logbase)| InputSpec {
            source,
            kind: InputKind::Data { logbase },
        })
        .collect()
}

fn config(readers: usize) -> EngineConfig {
    EngineConfig {
        num_threads: readers,
        reader_threads: readers,
        input_batch: 1,
        mem_limit_bytes: 16 << 20,
        ..EngineConfig::default()
    }
}

fn single_case(case: &str) {
    let resource = Arc::new(AtomicUsize::new(0));
    let reader = SingleReader {
        state: Mutex::new(SingleState::default()),
        changed: Condvar::new(),
        resource: Arc::clone(&resource),
        gated: case != "multi-drain",
        read_error: case == "single-error",
        calls: AtomicUsize::new(0),
    };
    let input = inputs(8);
    let engine = Engine {
        slice_size: 1024,
        inputs: &input,
        output_exponents: &[0],
        post_transform: None,
        config: config(if case == "multi-drain" { 2 } else { 1 }),
        kernel: Kernel::detect(),
    };
    let cancel = AtomicBool::new(case == "pre-cancel");
    let mut output = Vec::new();
    let mut fired = false;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        engine.run(
            &reader,
            &mut |_, _, bytes: &[u8]| {
                output.extend_from_slice(bytes);
                Ok(())
            },
            Some(&cancel),
            &mut |_, _, processed, _| {
                if processed == 1 && !fired && reader.gated {
                    fired = true;
                    let mut state = reader.state.lock().unwrap();
                    while !state.fourth_read {
                        state = reader.changed.wait(state).unwrap();
                    }
                    // Only batch0 was consumed. Completed sends of1/2 fill capacity2.
                    eprintln!("MARK_QUEUE_FULL");
                    if case == "cancel" {
                        cancel.store(true, Ordering::Relaxed);
                        eprintln!("MARK_CANCEL_SET");
                    }
                    state.release = true;
                    reader.changed.notify_all();
                    drop(state);
                    if case == "panic" {
                        panic!("owned consumer panic");
                    }
                }
            },
        )
    }));
    eprintln!("MARK_ENGINE_RETURN {case} {outcome:?}");
    if case == "panic" {
        let payload = outcome.expect_err("the owned progress panic must propagate");
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"owned consumer panic")
        );
        assert!(output.is_empty());
    } else {
        let result = outcome.unwrap();
        match case {
            "cancel" | "pre-cancel" => {
                assert!(matches!(result, Err(RsError::Cancelled)));
                assert!(output.is_empty());
                if case == "pre-cancel" {
                    assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
                }
            }
            "single-error" => {
                assert!(
                    matches!(result, Err(RsError::Io(ref error)) if error.kind()==io::ErrorKind::Other && error.to_string()=="owned single-reader failure")
                );
                assert!(output.is_empty());
            }
            "drain" | "multi-drain" => {
                result.unwrap();
                // Exponent0 coefficients are all1; XOR of constant inputs1..8 is8.
                assert_eq!(output, vec![8u8; 1024]);
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(resource.load(Ordering::SeqCst), 0);
    assert_eq!(Arc::strong_count(&resource), 2);
    drop(reader);
    assert_eq!(Arc::strong_count(&resource), 1);
    eprintln!("MARK_RESOURCE_RETIRED");
}

#[derive(Default)]
struct MultiState {
    entered: [bool; 9],
    release: [bool; 9],
    error_exited: bool,
}
#[derive(Default)]
struct Shared {
    state: Mutex<MultiState>,
    changed: Condvar,
}
struct ExitNotice(Arc<Shared>);
impl Drop for ExitNotice {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.error_exited = true;
        eprintln!("MARK_ERROR_PRODUCER_EXITED");
        self.0.changed.notify_all();
    }
}
thread_local! {
    // This schedules the test's error send. No prompt TLS-retirement claim is made.
    static ERROR_EXIT: RefCell<Option<ExitNotice>> = const { RefCell::new(None) };
}
struct MultiReader {
    shared: Arc<Shared>,
    resource: Arc<AtomicUsize>,
}
impl InputReader for MultiReader {
    fn read_input(&self, source: usize, _offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        let _activity = ReadActivity::begin(&self.resource);
        if [1, 5, 6, 7].contains(&source) {
            let mut state = self.shared.state.lock().unwrap();
            state.entered[source] = true;
            self.shared.changed.notify_all();
            while !state.release[source] {
                state = self.shared.changed.wait(state).unwrap();
            }
            drop(state);
            if source == 1 {
                ERROR_EXIT.with(|notice| {
                    *notice.borrow_mut() = Some(ExitNotice(Arc::clone(&self.shared)))
                });
                return Err(io::Error::other("owned multi-reader failure"));
            }
        }
        if source == 8 {
            eprintln!("MARK_ERROR_DEQUEUED_QUEUE_REFILLED");
        }
        bytes.fill(source as u8 + 1);
        Ok(())
    }
}

fn multi_error_case() {
    let resource = Arc::new(AtomicUsize::new(0));
    let shared = Arc::new(Shared::default());
    let reader = MultiReader {
        shared: Arc::clone(&shared),
        resource: Arc::clone(&resource),
    };
    let input = inputs(16);
    let engine = Engine {
        slice_size: 1024,
        inputs: &input,
        output_exponents: &[0],
        post_transform: None,
        config: config(2),
        kernel: Kernel::detect(),
    };
    let mut emitted = 0;
    let result = engine.run(
        &reader,
        &mut |_, _, bytes: &[u8]| {
            emitted += bytes.len();
            Ok(())
        },
        None,
        &mut |_, _, processed, _| {
            if !(1..=4).contains(&processed) {
                return;
            }
            let mut state = shared.state.lock().unwrap();
            match processed {
                1 => {
                    while !state.entered[5] {
                        state = shared.changed.wait(state).unwrap();
                    }
                    state.release[1] = true;
                }
                2 => {
                    // Error thread exits only after enqueuing error after batches3/4.
                    while !state.error_exited {
                        state = shared.changed.wait(state).unwrap();
                    }
                    state.release[5] = true;
                }
                3 => {
                    while !state.entered[6] {
                        state = shared.changed.wait(state).unwrap();
                    }
                    state.release[6] = true;
                }
                4 => {
                    while !state.entered[7] {
                        state = shared.changed.wait(state).unwrap();
                    }
                    eprintln!("MARK_ERROR_NEXT_QUEUE_FULL");
                    state.release[7] = true;
                }
                _ => unreachable!(),
            }
            shared.changed.notify_all();
        },
    );
    eprintln!("MARK_ENGINE_RETURN multi-error {result:?}");
    assert!(
        matches!(result, Err(RsError::Io(ref error)) if error.kind()==io::ErrorKind::Other && error.to_string()=="owned multi-reader failure")
    );
    assert_eq!(emitted, 0);
    assert_eq!(resource.load(Ordering::SeqCst), 0);
    assert_eq!(Arc::strong_count(&resource), 2);
    drop(reader);
    assert_eq!(Arc::strong_count(&resource), 1);
    eprintln!("MARK_RESOURCE_RETIRED");
}

#[test]
fn engine_shutdown_child() {
    let Ok(case) = std::env::var(CHILD_CASE) else {
        return;
    };
    if case == "multi-error" {
        multi_error_case();
    } else {
        single_case(&case);
    }
}
