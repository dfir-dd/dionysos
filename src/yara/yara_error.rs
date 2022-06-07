
use std::fmt::Display;

use yara::YaraError;

#[cfg(feature="evtx")]
use evtx::err::EvtxError;

//#[cfg(feature="reg")]

pub (crate) enum YaraScannerError {
    Yara(YaraError),

    #[cfg(feature="evtx")]
    Evtx(EvtxError),
}

impl Display for YaraScannerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yara(why) => write!(f, "Yara Error: {}", why),

            #[cfg(feature="evtx")]
            Self::Evtx(why) => write!(f, "Evtx Error: {}", why)
        }
    }
}

impl From<EvtxError> for YaraScannerError {
    fn from(err: EvtxError) -> Self {
        Self::Evtx(err)
    }
}

impl From<YaraError> for YaraScannerError {
    fn from(err: YaraError) -> Self {
        Self::Yara(err)
    }
}