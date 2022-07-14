
use std::{fmt::Display};

use yara::YaraError;

#[cfg(feature="scan_evtx")]
use evtx::err::EvtxError;

//#[cfg(feature="reg")]
pub (crate) enum YaraScannerError {
    Yara(YaraError),

    #[cfg(feature="scan_evtx")]
    Evtx(EvtxError),

    #[cfg(feature="scan_reg")]
    Reg(binread::Error),
}

impl Display for YaraScannerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yara(why) => write!(f, "Yara Error: {}", why),

            #[cfg(feature="scan_evtx")]
            Self::Evtx(why) => write!(f, "Evtx Error: {}", why),

            #[cfg(feature="scan_reg")]
            Self::Reg(why) => write!(f, "Registry Error: {}", why),
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


impl From<binread::Error> for YaraScannerError {
    fn from(err: binread::Error) -> Self {
        Self::Reg(err)
    }
}