use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error with sqlx")]
    DatabaseError(#[from] sqlx::Error),

    #[error("the resource could not be found")]
    NotFound,

    #[error("the resource already exists")]
    OnConflict,
}
