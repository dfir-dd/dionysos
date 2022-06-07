use yara::{Match, YrString};


pub struct YaraString {
    pub identifier: String,
    pub matches: Vec<Match>,
}

impl From<YrString<'_>> for YaraString {
    fn from(s: YrString<'_>) -> Self {
        Self {
            identifier: s.identifier.to_owned(),
            matches: s.matches
        }
    }
}