use preen_core::FileSystemPort;
pub struct DummyAdapter;

impl FileSystemPort for DummyAdapter {
    fn find_cleanable_items(&self) -> Vec<String> {
        vec!["/tmp/dummy_cache".to_string()]
    }
}
