use jsonrpsee::types::ErrorObjectOwned;

/// Standard JSON-RPC 2.0 error codes with Bitcoin compatibility
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum RpcErrorCode {
    // Standard JSON-RPC 2.0 errors
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,

    // Bitcoin-compatible custom errors (range -1 to -28)
    MiscError = -1,
    TypeNotSupported = -3,
    InvalidAddressOrKey = -5,
    OutOfMemory = -7,
    InvalidParameter = -8,
    DatabaseError = -20,
    DeserializationError = -22,
    VerifyError = -25,
    VerifyRejected = -26,
    InWarmup = -28,
}

/// RPC error type
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Wallet not loaded")]
    WalletNotLoaded,

    #[error("Transaction not found: {0}")]
    TxNotFound(String),

    #[error("Block not found: {0}")]
    BlockNotFound(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Mempool error: {0}")]
    Mempool(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl RpcError {
    /// Convert RpcError to JSON-RPC ErrorObjectOwned
    pub fn into_error_object(self) -> ErrorObjectOwned {
        match self {
            RpcError::InvalidParameter(msg) => {
                ErrorObjectOwned::owned(
                    RpcErrorCode::InvalidParameter as i32,
                    msg,
                    None::<()>,
                )
            }
            RpcError::InvalidAddress(msg) => {
                ErrorObjectOwned::owned(
                    RpcErrorCode::InvalidAddressOrKey as i32,
                    msg,
                    None::<()>,
                )
            }
            RpcError::Database(msg) => {
                ErrorObjectOwned::owned(
                    RpcErrorCode::DatabaseError as i32,
                    msg,
                    None::<()>,
                )
            }
            RpcError::WalletNotLoaded => {
                ErrorObjectOwned::owned(
                    RpcErrorCode::InvalidAddressOrKey as i32,
                    "Wallet not loaded. Start node with --wallet flag.".to_string(),
                    None::<()>,
                )
            }
            RpcError::TxNotFound(msg) => {
                ErrorObjectOwned::owned(
                    RpcErrorCode::InvalidAddressOrKey as i32,
                    format!("Transaction not found: {}", msg),
                    None::<()>,
                )
            }
            RpcError::BlockNotFound(msg) => {
                ErrorObjectOwned::owned(
                    RpcErrorCode::InvalidAddressOrKey as i32,
                    format!("Block not found: {}", msg),
                    None::<()>,
                )
            }
            RpcError::InvalidTransaction(msg) => {
                ErrorObjectOwned::owned(
                    RpcErrorCode::VerifyRejected as i32,
                    format!("Invalid transaction: {}", msg),
                    None::<()>,
                )
            }
            RpcError::Mempool(msg) => {
                ErrorObjectOwned::owned(
                    RpcErrorCode::MiscError as i32,
                    format!("Mempool error: {}", msg),
                    None::<()>,
                )
            }
            RpcError::Network(msg) => {
                ErrorObjectOwned::owned(
                    RpcErrorCode::MiscError as i32,
                    format!("Network error: {}", msg),
                    None::<()>,
                )
            }
            RpcError::Deserialization(msg) => {
                ErrorObjectOwned::owned(
                    RpcErrorCode::DeserializationError as i32,
                    msg,
                    None::<()>,
                )
            }
            RpcError::Internal(msg) => {
                ErrorObjectOwned::owned(
                    RpcErrorCode::InternalError as i32,
                    msg,
                    None::<()>,
                )
            }
        }
    }
}
