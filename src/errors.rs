
use thiserror::Error;
use acvm::acir::BlackBoxFunc;


#[derive(Debug, Error)]
enum FeatureError {
    #[error("Could not slice field element")]
    FieldElementSlice {
        source: std::array::TryFromSliceError,
    },
    #[error("Expected a Vec of length {0} but it was {1}")]
    FieldToArray(usize, usize),
}

#[derive(Debug, Error)]
enum Error {
    #[error("The value {0} overflows in the pow2ceil function")]
    Pow2CeilOverflow(u32),

    #[error("Malformed Black Box Function: {0} - {1}")]
    MalformedBlackBoxFunc(BlackBoxFunc, String),

    #[error("Unsupported Black Box Function: {0}")]
    UnsupportedBlackBoxFunc(BlackBoxFunc),

    #[error(transparent)]
    FromFeature(#[from] FeatureError),
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct BackendError(#[from] Error);

impl From<FeatureError> for BackendError {
    fn from(value: FeatureError) -> Self {
        value.into()
    }
}