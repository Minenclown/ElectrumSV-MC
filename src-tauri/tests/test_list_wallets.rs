// tests/test_list_wallets.rs — Tests for list_wallets logic
//
// Tests the file scanning logic without a Tauri runtime.
// AUD-023 fix: Uses hermetic temp dirs, no live data paths.

use electrumsv_mc_lib::db::connection;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_test_dir(test_name: &str) -> std::path::PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("electrumsv_mc_it_{}_{}", test_name, id));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_list_wallet_files_finds_sqlite() {
    let temp_dir = unique_test_dir("it_finds");
    std::fs::write(temp_dir.join("Test.sqlite"), b"sqlite data").unwrap();

    let wallets = connection::list_wallet_files(temp_dir.to_str().unwrap()).unwrap();

    assert!(!wallets.is_empty(), "Should find at least one wallet file");

    let test_wallet = wallets.iter().find(|w| w.name == "Test");
    assert!(test_wallet.is_some(), "Should find Test.sqlite wallet");

    let w = test_wallet.unwrap();
    assert!(
        w.path.ends_with("Test.sqlite"),
        "Path should end with Test.sqlite"
    );
    assert!(w.size_bytes > 0, "Wallet file should not be empty");

    std::fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_list_wallet_files_nonexistent_dir() {
    let wallets = connection::list_wallet_files("/nonexistent/path/12345").unwrap();
    assert!(
        wallets.is_empty(),
        "Nonexistent dir should return empty list"
    );
}

#[test]
fn test_list_wallet_files_ignores_non_sqlite() {
    let temp_dir = unique_test_dir("it_ignores");
    std::fs::write(temp_dir.join("wallet.bak"), b"backup").unwrap();
    std::fs::write(temp_dir.join("wallet.bak-shm"), b"shm").unwrap();
    std::fs::write(temp_dir.join("wallet.bak-wal"), b"wal").unwrap();
    std::fs::write(temp_dir.join("real.sqlite"), b"sqlite").unwrap();

    let wallets = connection::list_wallet_files(temp_dir.to_str().unwrap()).unwrap();

    for w in &wallets {
        assert!(
            w.path.ends_with(".sqlite"),
            "Should only find .sqlite files, got: {}",
            w.path
        );
    }
    assert_eq!(wallets.len(), 1, "Should find exactly one .sqlite file");

    std::fs::remove_dir_all(&temp_dir).ok();
}
