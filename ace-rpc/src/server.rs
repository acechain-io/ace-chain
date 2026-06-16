//! RPC server startup and lifecycle.
//!
//! Security: The server binds to loopback (127.0.0.1) only by default.
//! For mainnet or any external exposure, use a reverse proxy with TLS,
//! rate limiting, and optional authentication; do not bind to 0.0.0.0 without them.

use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::server::Server;
use jsonrpsee::server::ServerHandle;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use ace_model::block_store::BlockStore;

use crate::error::RpcError;
use crate::eth_rpc::{EthRpcImpl, EthRpcServer};
use crate::hfi_pay_rpc::{HfiPayRpcImpl, HfiPayRpcServer, HfiPayState};
use crate::methods::{AceRpcImpl, AceRpcServer, RpcState, SolanaRpcServer};

/// JSON-RPC server for ACE Chain.
pub struct RpcServer;

impl RpcServer {
    /// Start the RPC server on the given port (loopback only).
    ///
    /// Registers both `ace_*` and `eth_*`/`net_*`/`web3_*` method namespaces
    /// so that both ACE-native tools and standard Ethereum wallets can connect.
    ///
    /// Returns a `ServerHandle` that can be used to stop the server.
    pub async fn start<B: BlockStore + Send + Sync + 'static>(
        bind_addr: &str,
        port: u16,
        shared: Arc<RpcState<B>>,
        hfi_pay_state: Arc<HfiPayState>,
    ) -> Result<ServerHandle, RpcError> {
        let addr: SocketAddr = format!("{bind_addr}:{port}")
            .parse()
            .map_err(|e| RpcError::ServerError(format!("invalid rpc_bind_addr: {e}")))?;
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);
        let middleware = tower::ServiceBuilder::new().layer(cors);
        let server = Server::builder()
            .set_http_middleware(middleware)
            .max_request_body_size(2 * 1024 * 1024) // 2 MB
            .max_connections(1024)
            .build(addr)
            .await
            .map_err(|e| RpcError::ServerError(e.to_string()))?;

        // ACE-native RPC methods (ace_*)
        let ace_rpc = AceRpcImpl {
            shared: shared.clone(),
        };
        let mut module = AceRpcServer::into_rpc(ace_rpc);

        // Ethereum-compatible RPC methods (eth_*, net_*, web3_*)
        let eth_rpc = EthRpcImpl {
            shared: shared.clone(),
        };
        module
            .merge(eth_rpc.into_rpc())
            .map_err(|e| RpcError::ServerError(format!("failed to merge eth_rpc: {e}")))?;

        // Minimal Solana-compatible RPC methods for Phantom/native transfers.
        let solana_rpc = AceRpcImpl {
            shared: shared.clone(),
        };
        module
            .merge(SolanaRpcServer::into_rpc(solana_rpc))
            .map_err(|e| RpcError::ServerError(format!("failed to merge solana_rpc: {e}")))?;

        // HFI Pay RPC methods (ace_hfiPay*)
        let hfi_pay_rpc = HfiPayRpcImpl {
            shared: shared.clone(),
            hfi_pay: hfi_pay_state,
        };
        module
            .merge(HfiPayRpcServer::into_rpc(hfi_pay_rpc))
            .map_err(|e| RpcError::ServerError(format!("failed to merge hfi_pay_rpc: {e}")))?;

        let handle = server.start(module);

        info!(%addr, "RPC server started (ace_* + eth_* + Solana + HFI Pay namespaces)");

        Ok(handle)
    }
}
