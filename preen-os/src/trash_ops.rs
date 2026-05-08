use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashMove {
    pub original_path: PathBuf,
    pub trashed_path: PathBuf,
}

pub fn move_path_to_trash(path: &Path) -> Result<TrashMove, String> {
    if let Err(error) = trash::delete(path) {
        move_path_to_home_trash(path).map_err(|fallback_error| {
            format!(
                "trash failed: {}; fallback failed: {}: {error}",
                path.display(),
                fallback_error
            )
        })
    } else {
        Ok(TrashMove {
            original_path: path.to_path_buf(),
            trashed_path: PathBuf::new(),
        })
    }
}

pub fn move_path_to_home_trash(path: &Path) -> Result<TrashMove, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    let trash_dir = home_trash_files_dir(&home);
    fs::create_dir_all(&trash_dir).map_err(|error| format!("create trash dir failed: {error}"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| "path has no file name".to_string())?;
    let mut candidate = trash_dir.join(file_name);
    let mut suffix = 1usize;
    while candidate.exists() {
        candidate = trash_dir.join(format!("{}.{}", file_name.to_string_lossy(), suffix));
        suffix = suffix.saturating_add(1);
    }
    loop {
        match fs::rename(path, &candidate) {
            Ok(()) => {
                return Ok(TrashMove {
                    original_path: path.to_path_buf(),
                    trashed_path: candidate,
                });
            }
            Err(error) if is_cross_device_error(&error) => {
                copy_remove_path(path, &candidate).map_err(|copy_error| {
                    let _ = cleanup_path(&candidate);
                    format!(
                        "cross-device move failed: {} -> {}: {copy_error}",
                        path.display(),
                        candidate.display()
                    )
                })?;
                return Ok(TrashMove {
                    original_path: path.to_path_buf(),
                    trashed_path: candidate,
                });
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                candidate = trash_dir.join(format!("{}.{}", file_name.to_string_lossy(), suffix));
                suffix = suffix.saturating_add(1);
            }
            Err(error) => {
                return Err(format!(
                    "move to trash failed: {} -> {}: {error}",
                    path.display(),
                    candidate.display()
                ));
            }
        }
    }
}

fn is_cross_device_error(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(18)
}

fn copy_remove_path(source: &Path, destination: &Path) -> Result<(), String> {
    copy_path(source, destination)?;
    cleanup_path(source)
}

fn copy_path(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("read metadata failed: {}: {error}", source.display()))?;
    if metadata.file_type().is_symlink() {
        copy_symlink(source, destination)
    } else if metadata.is_dir() {
        fs::create_dir_all(destination)
            .map_err(|error| format!("create dir failed: {}: {error}", destination.display()))?;
        let entries = fs::read_dir(source)
            .map_err(|error| format!("read dir failed: {}: {error}", source.display()))?;
        for entry in entries {
            let entry = entry
                .map_err(|error| format!("read dir entry failed: {}: {error}", source.display()))?;
            copy_path(&entry.path(), &destination.join(entry.file_name()))?;
        }
        copy_permissions(&metadata, destination)?;
        Ok(())
    } else if metadata.is_file() {
        fs::copy(source, destination).map(|_| ()).map_err(|error| {
            format!(
                "copy file failed: {} -> {}: {error}",
                source.display(),
                destination.display()
            )
        })?;
        copy_permissions(&metadata, destination)
    } else {
        Err(format!("unsupported file type: {}", source.display()))
    }
}

fn copy_permissions(metadata: &fs::Metadata, destination: &Path) -> Result<(), String> {
    fs::set_permissions(destination, metadata.permissions())
        .map_err(|error| format!("set permissions failed: {}: {error}", destination.display()))
}

#[cfg(unix)]
fn copy_symlink(source: &Path, destination: &Path) -> Result<(), String> {
    let target = fs::read_link(source)
        .map_err(|error| format!("read symlink failed: {}: {error}", source.display()))?;
    std::os::unix::fs::symlink(&target, destination).map_err(|error| {
        format!(
            "copy symlink failed: {} -> {}: {error}",
            source.display(),
            destination.display()
        )
    })
}

#[cfg(not(unix))]
fn copy_symlink(source: &Path, destination: &Path) -> Result<(), String> {
    fs::copy(source, destination).map(|_| ()).map_err(|error| {
        format!(
            "copy symlink target failed: {} -> {}: {error}",
            source.display(),
            destination.display()
        )
    })
}

fn cleanup_path(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read metadata failed: {}: {error}", path.display()))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
            .map_err(|error| format!("remove dir failed: {}: {error}", path.display()))
    } else {
        fs::remove_file(path)
            .map_err(|error| format!("remove file failed: {}: {error}", path.display()))
    }
}

fn home_trash_files_dir(home: &Path) -> PathBuf {
    if cfg!(target_os = "linux") {
        home.join(".local/share/Trash/files")
    } else {
        home.join(".Trash")
    }
}

pub fn restore_trashed_path(original_path: &Path, trashed_path: &Path) -> Result<(), String> {
    if !trashed_path.exists() {
        return Err(format!("trash item not found: {}", trashed_path.display()));
    }
    if original_path.exists() {
        return Err(format!(
            "restore target already exists: {}",
            original_path.display()
        ));
    }
    if let Some(parent) = original_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create restore parent failed: {}: {error}",
                parent.display()
            )
        })?;
    }
    match fs::rename(trashed_path, original_path) {
        Ok(()) => Ok(()),
        Err(error) if is_cross_device_error(&error) => {
            copy_remove_path(trashed_path, original_path).map_err(|copy_error| {
                let _ = cleanup_path(original_path);
                format!(
                    "cross-device restore failed: {} -> {}: {copy_error}",
                    trashed_path.display(),
                    original_path.display()
                )
            })
        }
        Err(error) => Err(format!(
            "restore failed: {} -> {}: {error}",
            trashed_path.display(),
            original_path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn env_lock() -> MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => unsafe {
                    std::env::set_var(self.key, value);
                },
                None => unsafe {
                    std::env::remove_var(self.key);
                },
            }
        }
    }

    #[test]
    fn home_trash_move_uses_unique_target_and_restore_roundtrips() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = EnvVarGuard::set("HOME", dir.path().to_string_lossy().as_ref());
        let source = dir.path().join("item.txt");
        fs::write(&source, "a").unwrap();
        let trash_dir = home_trash_files_dir(dir.path());
        fs::create_dir_all(&trash_dir).unwrap();
        fs::write(trash_dir.join("item.txt"), "existing").unwrap();

        let moved = move_path_to_home_trash(&source).unwrap();

        assert_eq!(moved.trashed_path, trash_dir.join("item.txt.1"));
        assert!(!source.exists());
        assert!(moved.trashed_path.exists());

        restore_trashed_path(&moved.original_path, &moved.trashed_path).unwrap();
        assert!(source.exists());
        assert!(!moved.trashed_path.exists());
    }

    #[test]
    fn home_trash_files_dir_uses_platform_convention() {
        let home = PathBuf::from("/home/demo");
        let expected = if cfg!(target_os = "linux") {
            home.join(".local/share/Trash/files")
        } else {
            home.join(".Trash")
        };

        assert_eq!(home_trash_files_dir(&home), expected);
    }

    #[test]
    fn copy_remove_path_moves_directory_trees() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("Demo.app");
        let nested = source.join("Contents").join("Resources");
        fs::create_dir_all(&nested).unwrap();
        fs::write(source.join("Contents").join("Info.plist"), "plist").unwrap();
        fs::write(nested.join("asset.bin"), "asset").unwrap();
        let destination = dir.path().join("Trash").join("Demo.app");

        copy_remove_path(&source, &destination).unwrap();

        assert!(!source.exists());
        assert_eq!(
            fs::read_to_string(destination.join("Contents").join("Info.plist")).unwrap(),
            "plist"
        );
        assert_eq!(
            fs::read_to_string(
                destination
                    .join("Contents")
                    .join("Resources")
                    .join("asset.bin")
            )
            .unwrap(),
            "asset"
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_remove_path_preserves_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("Demo.app");
        fs::create_dir_all(&source).unwrap();
        std::os::unix::fs::symlink("../Shared", source.join("SharedLink")).unwrap();
        let destination = dir.path().join("Trash").join("Demo.app");

        copy_remove_path(&source, &destination).unwrap();

        assert!(!source.exists());
        assert_eq!(
            fs::read_link(destination.join("SharedLink")).unwrap(),
            PathBuf::from("../Shared")
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_remove_path_preserves_file_and_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("Demo.app");
        let executable_dir = source.join("Contents").join("MacOS");
        fs::create_dir_all(&executable_dir).unwrap();
        fs::set_permissions(&executable_dir, fs::Permissions::from_mode(0o750)).unwrap();
        let executable = executable_dir.join("demo");
        fs::write(&executable, "bin").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let destination = dir.path().join("Trash").join("Demo.app");

        copy_remove_path(&source, &destination).unwrap();

        let copied_dir_mode = fs::metadata(destination.join("Contents").join("MacOS"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let copied_file_mode =
            fs::metadata(destination.join("Contents").join("MacOS").join("demo"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;

        assert_eq!(copied_dir_mode, 0o750);
        assert_eq!(copied_file_mode, 0o755);
    }

    #[test]
    fn restore_refuses_to_replace_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("item.txt");
        let trashed = dir.path().join(".Trash").join("item.txt");
        fs::create_dir_all(trashed.parent().unwrap()).unwrap();
        fs::write(&original, "new").unwrap();
        fs::write(&trashed, "old").unwrap();

        let error = restore_trashed_path(&original, &trashed).unwrap_err();

        assert!(error.contains("restore target already exists"));
        assert_eq!(fs::read_to_string(&original).unwrap(), "new");
        assert_eq!(fs::read_to_string(&trashed).unwrap(), "old");
    }
}
