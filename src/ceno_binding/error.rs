use std::fmt::Debug;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ProofError(#[from] nimue::ProofError),
}
