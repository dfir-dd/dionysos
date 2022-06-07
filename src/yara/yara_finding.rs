use super::yara_string::YaraString;

pub struct YaraFinding {
    pub identifier: String,
    pub namespace: String,
    //pub metadatas: Vec<Metadata<'r>>,
    pub tags: Vec<String>,
    pub strings: Vec<YaraString>,
    pub value_data: Option<String>
}

impl From<yara::Rule<'_>> for YaraFinding {
    fn from(rule: yara::Rule) -> Self {
        Self {
            identifier: rule.identifier.to_owned(),
            namespace: rule.namespace.to_owned(),
            tags: rule.tags.iter().map(|s|String::from(*s)).collect(),
            strings: rule.strings.into_iter().map(|s| s.into()).collect(),
            value_data: None
        }
    }
}

impl YaraFinding {
    pub fn with_value_data(mut self, data: String) -> Self {
        self.value_data = Some(data);
        self
    }
}