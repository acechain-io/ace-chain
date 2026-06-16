//! ACE DeFi Relayer - Main entry point
//!
//! Runs ingress and egress monitoring loops concurrently

use ace_defi_relayer::{config::RelayerConfig, egress::monitor_egress, ingress::monitor_ingress};
use std::env;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    // Initialize logging
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "ace_defi_relayer=debug,info");
    }
    tracing_subscriber::fmt::init();

    info!("=== ACE DeFi Relayer Starting ===");

    // Load configuration
    let config = match RelayerConfig::from_env() {
        Ok(cfg) => {
            info!("Configuration loaded successfully");
            cfg
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            error!("Required environment variables:");
            error!("  - ACE_RPC_URL: ACE Chain RPC endpoint");
            error!("  - RELAYER_PRIVATE_KEY: Ed25519 private key (hex)");
            error!("Optional environment variables:");
            error!("  - ETH_RPC_URL: Ethereum RPC endpoint");
            error!("  - ETH_BRIDGE_CONTRACT: Ethereum bridge contract address");
            error!("  - BSC_RPC_URL: BSC RPC endpoint");
            error!("  - BSC_BRIDGE_CONTRACT: BSC bridge contract address");
            error!("  - POLL_INTERVAL: Polling interval in seconds (default: 10)");
            error!("  - MAX_DEPOSIT: Maximum deposit amount (default: 1e18)");
            error!("  - ORACLE_TYPE: Oracle type - 'mock' or 'coingecko' (default: mock)");
            std::process::exit(1);
        }
    };

    info!("Relayer configuration:");
    info!("  - ACE RPC: {}", config.ace_rpc_url);
    info!("  - Poll interval: {} seconds", config.poll_interval_secs);
    info!(
        "  - Supported chains: {:?}",
        config.chains.keys().collect::<Vec<_>>()
    );

    // Spawn monitoring tasks for each configured chain
    let mut ingress_tasks = vec![];

    for (chain_name, chain_config) in &config.chains {
        if let Some(bridge_contract) = &chain_config.bridge_contract {
            let task = tokio::spawn({
                let chain_name = chain_name.clone();
                let rpc_url = chain_config.rpc_url.clone();
                let bridge_contract = bridge_contract.clone();
                let finality_blocks = chain_config.finality_blocks;
                let block_time_secs = chain_config.block_time_secs;
                let ace_rpc_url = config.ace_rpc_url.clone();
                let relayer_private_key = config.relayer_private_key.clone();
                let relayer_id = format!("relayer-{}", chrono::Utc::now().timestamp());
                let max_deposit_per_tx = config.max_deposit_per_tx;
                let poll_interval_secs = config.poll_interval_secs;

                async move {
                    if let Err(e) = monitor_ingress(
                        chain_name,
                        rpc_url,
                        bridge_contract,
                        finality_blocks,
                        block_time_secs,
                        ace_rpc_url,
                        relayer_private_key,
                        relayer_id,
                        max_deposit_per_tx,
                        poll_interval_secs,
                    )
                    .await
                    {
                        error!("Ingress monitoring error: {}", e);
                    }
                }
            });

            ingress_tasks.push(task);
        }
    }

    // Spawn egress monitoring task
    let ace_rpc_url = config.ace_rpc_url.clone();
    let chains = config.chains.clone();
    let relayer_private_key = config.relayer_private_key.clone();
    let poll_interval_secs = config.poll_interval_secs;
    let egress_task = tokio::spawn(async move {
        if let Err(e) =
            monitor_egress(ace_rpc_url, chains, relayer_private_key, poll_interval_secs).await
        {
            error!("Egress monitoring error: {}", e);
        }
    });

    info!("All monitoring tasks started");

    // Wait for all tasks (they run forever)
    for task in ingress_tasks {
        let _ = task.await;
    }

    let _ = egress_task.await;

    error!("All monitoring tasks exited unexpectedly!");
}
