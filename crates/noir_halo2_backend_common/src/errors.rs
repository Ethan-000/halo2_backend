use acvm::acir::BlackBoxFunc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FeatureError {
    #[error("Could not slice field element")]
    _FieldElementSlice {
        source: std::array::TryFromSliceError,
    },
    #[error("Expected a Vec of length {0} but it was {1}")]
    _FieldToArray(usize, usize),
}

#[derive(Debug, Error)]
pub enum CRSError {
    #[error("Failed to deserialize CRS")]
    _Deserialize { source: Box<bincode::ErrorKind> },
    #[error("Failed to serialize CRS")]
    _Serialize { source: Box<bincode::ErrorKind> },

    #[error("Failed to build request '{url}' ({source})")]
    Request { url: String, source: reqwest::Error },
    #[error("Failed to GET from '{url}' ({source})")]
    Fetch { url: String, source: reqwest::Error },
    #[error("Failed to get content length from '{url}'")]
    Length { url: String },
    #[error("Error while downloading file")]
    Download { source: reqwest::Error },
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Error)]
pub enum Error {
    #[error("The value {0} overflows in the pow2ceil function")]
    _Pow2CeilOverflow(u32),

    #[error("Malformed Black Box Function: {0} - {1}")]
    MalformedBlackBoxFunc(BlackBoxFunc, String),

    #[error("Unsupported Black Box Function: {0}")]
    _UnsupportedBlackBoxFunc(BlackBoxFunc),

    #[error(transparent)]
    FromFeature(#[from] FeatureError),

    #[error(transparent)]
    CRS(#[from] CRSError),
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct BackendError(#[from] Error);

impl From<FeatureError> for BackendError {
    fn from(value: FeatureError) -> Self {
        value.into()
    }
}

impl From<CRSError> for BackendError {
    fn from(value: CRSError) -> Self {
        value.into()
    }
}
