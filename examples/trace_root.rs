//! Legacy CLI for the isolated trusted-image worker.
fn main() {
    rpweld::trace_worker::worker_entry(std::env::args_os().skip(1));
}
