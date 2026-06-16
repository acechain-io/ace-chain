use thiserror::Error;

#[derive(Error, Debug)]
pub enum MoveError {
    #[error("Invalid Move transaction format: {0}")]
    InvalidFormat(String),

    #[error("Invalid bytecode: {0}")]
    InvalidBytecode(String),

    #[error("Bytecode verification failed: {0}")]
    VerificationFailed(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("Type mismatch: {0}")]
    TypeMismatch(String),

    #[error("Insufficient gas: {0}")]
    InsufficientGas(String),

    #[error("Module already exists: {0}")]
    ModuleAlreadyExists(String),

    #[error("State error: {0}")]
    StateError(String),

    #[error("Serde error: {0}")]
    SerdeError(#[from] serde_json::error::Error),

    #[error("Serialization error: {0}")]
    BincodeError(#[from] bincode::Error),
}

pub type MoveResult<T> = Result<T, MoveError>;
