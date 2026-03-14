use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum CoreError {
    #[error("io error: {message}")]
    Io { message: String },
    #[error("config error: {message}")]
    Config { message: String },
    #[error("validation error: {message}")]
    Validation { message: String },
    #[error("store error: {message}")]
    Store { message: String },
    #[error("os error: {message}")]
    Os { message: String },
    #[error("internal error: {message}")]
    Internal { message: String },
    #[error("compat error: {message}")]
    Compat { message: String },
}
