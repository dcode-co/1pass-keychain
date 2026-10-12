//! The `kc` binary: hardens the process, then runs [`kc_cli::run`] on a single-threaded
//! tokio runtime.

fn main() {
    kc_cli::harden::harden_process();
    kc_cli::interrupt::install();
    let code = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => {
            let mut host = kc_cli::RealHost::new();
            runtime.block_on(kc_cli::run(&mut host, std::env::args_os()))
        }
        Err(e) => {
            eprintln!("kc: can't start: {e}");
            kc_cli::error::EXIT_FAILURE
        }
    };
    std::process::exit(code);
}
