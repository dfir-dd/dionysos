use std::collections::HashMap;

use duplicate::duplicate_item;


#[derive(Default)]
pub (crate) struct YaraExternals {
    filename: Option<String>,
    filepath: Option<String>,
    extension: Option<String>,
    filetype: Option<String>,
    md5: Option<String>,
    owner: Option<String>
}

impl YaraExternals {
    pub fn to_hashmap(&self) -> HashMap<&str, &str> {
        let mut res = HashMap::new();

        if let Some(x) = &self.filename  { res.insert("filename",  x.as_str());}
        if let Some(x) = &self.filepath  { res.insert("filepath",  x.as_str());}
        if let Some(x) = &self.extension { res.insert("extension", x.as_str());}
        if let Some(x) = &self.filetype  { res.insert("filetype",  x.as_str());}
        if let Some(x) = &self.md5       { res.insert("md5",       x.as_str());}
        if let Some(x) = &self.owner     { res.insert("owner",     x.as_str());}

        res
    }

    #[duplicate_item (
        method_name      variable_name;
        [with_filename]  [filename];
        [with_filepath]  [filepath];
        [with_extension] [extension];
        [with_filetype]  [filetype];
        [with_md5]       [md5];
        [with_owner]     [owner]
    )]
    pub fn method_name(mut self, variable_name: String) -> Self {
        self.variable_name = Some(variable_name);
        self
    }

    pub fn dummy() -> Self {
        Self::default()
            .with_filename("-".to_owned())
            .with_filepath("-".to_owned())
            .with_extension("-".to_owned())
            .with_filetype("-".to_owned())
            .with_md5("-".to_owned())
            .with_owner("dummy".to_owned())
    }
}