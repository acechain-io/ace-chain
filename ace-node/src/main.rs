//! ACE Chain node entry point.

use std::io::{self, IsTerminal};

use ace_node::cli::Cli;
use ace_node::node::Node;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Avoid ANSI escape codes (ESC 0x1b) in log files: only colorize when stderr is an
    // interactive terminal and NO_COLOR is unset (https://no-color.org/).
    let ansi = std::env::var_os("NO_COLOR").is_none() && io::stderr().is_terminal();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_ansi(ansi)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    // Limit rayon global thread pool.  On devnet all 3 nodes share the same
    // machine; without a cap each node spawns num_cpus threads and the
    // resulting over-subscription causes consensus timeouts during heavy
    // ML-DSA-44 parallel verification.  4 threads per node is a safe default
    // for a 12-core machine (3 nodes × 4 = 12).
    let rayon_threads = std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(4);
    rayon::ThreadPoolBuilder::new()
        .num_threads(rayon_threads)
        .build_global()
        .ok(); // ignore if already initialized

    tracing::info!(rayon_threads, "ACE Chain node starting");

    let node = Node::from_cli(cli)?;
    node.run().await
}
