use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub struct CleanFixture {
    _temp: tempfile::TempDir,
    pub root: PathBuf,
}

impl CleanFixture {
    pub fn with_files(files: &[(&str, &[u8])]) -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("cache");
        std::fs::create_dir_all(&root).expect("create cache dir");
        for (name, content) in files {
            std::fs::write(root.join(name), content).expect("write file");
        }
        Self { _temp: temp, root }
    }

    pub fn empty() -> Self {
        Self::with_files(&[])
    }

    pub fn create_symlink_to_outside(&self, link_name: &str, outside_content: &[u8]) -> PathBuf {
        let outside = self
            .root
            .parent()
            .expect("cache parent")
            .join("outside-target.txt");
        std::fs::write(&outside, outside_content).expect("write outside target");
        let link_path = self.root.join(link_name);
        std::os::unix::fs::symlink(&outside, &link_path).expect("create symlink");
        link_path
    }
}

pub struct CleanEnvGuard {
    _guard: std::sync::MutexGuard<'static, ()>,
    set_max_items: bool,
    set_preview_limit: bool,
    set_strategy: bool,
}

impl CleanEnvGuard {
    pub fn set(root: &Path, max_items: Option<&str>) -> Self {
        let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));
        let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: integration tests mutate process env under a global lock.
        unsafe {
            std::env::set_var("PREEN_CLEAN_PATHS", root.as_os_str());
            std::env::set_var("PREEN_CLEAN_PREVIEW_LIMIT", "20");
        }
        let mut set_max_items = false;
        if let Some(value) = max_items {
            // SAFETY: integration tests mutate process env under a global lock.
            unsafe {
                std::env::set_var("PREEN_CLEAN_MAX_ITEMS", value);
            }
            set_max_items = true;
        }
        Self {
            _guard: guard,
            set_max_items,
            set_preview_limit: true,
            set_strategy: false,
        }
    }

    pub fn set_with_strategy(root: &Path, max_items: Option<&str>, strategy: &str) -> Self {
        let mut env = Self::set(root, max_items);
        // SAFETY: integration tests mutate process env under a global lock.
        unsafe {
            std::env::set_var("PREEN_CLEAN_STRATEGY", strategy);
        }
        env.set_strategy = true;
        env
    }
}

impl Drop for CleanEnvGuard {
    fn drop(&mut self) {
        // SAFETY: integration tests mutate process env under a global lock.
        unsafe {
            std::env::remove_var("PREEN_CLEAN_PATHS");
            if self.set_max_items {
                std::env::remove_var("PREEN_CLEAN_MAX_ITEMS");
            }
            if self.set_preview_limit {
                std::env::remove_var("PREEN_CLEAN_PREVIEW_LIMIT");
            }
            if self.set_strategy {
                std::env::remove_var("PREEN_CLEAN_STRATEGY");
            }
        }
    }
}

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
