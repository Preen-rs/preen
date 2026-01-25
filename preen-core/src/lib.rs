use std::path::PathBuf;

#[derive(Debug)]
pub enum Command {
    StartScan { path: PathBuf },
    StartClean,
    Quit,
}

#[derive(Debug)]
pub enum Event {
    ScanProgress(f32),
    ScanCompleted,
    Error(String),
}

pub trait FileSystemPort {
    fn find_cleanable_items(&self) -> Vec<String>;
}
