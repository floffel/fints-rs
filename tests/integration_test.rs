//! Integration tests for the fints crate against a python-fints mock server.
//!
//! These tests use the new protocol state machine (`Dialog<New>` → `Dialog<Synced>` →
//! `Dialog<Open>` etc.) and verify the full wire protocol (parser, serializer,
//! message envelope, transport) works end-to-end.
//!
//! Requirements:
//! - Python 3 must be available as `python3`
//! - No external Python packages needed (mock server uses stdlib only)

use std::io::BufRead;
use std::process::{Child, Command, Stdio};

use fints::protocol::*;
use fints::{Blz, UserId, Pin, ProductId, SegmentType};

/// Helper: spawn the Python mock server and return (child process, port).
fn spawn_mock_server() -> Option<(Child, u16)> {
    let mock_script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("mock_server.py");

    if !mock_script.exists() {
        eprintln!("Mock server script not found at {:?}", mock_script);
        return None;
    }

    let mut child = Command::new("python3")
        .arg(&mock_script)
        .arg("0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let stdout = child.stdout.take()?;
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;

    if !line.starts_with("READY:") {
        eprintln!("Unexpected mock server output: {}", line);
        child.kill().ok();
        return None;
    }

    let port: u16 = line.trim().strip_prefix("READY:")?.parse().ok()?;
    std::thread::sleep(std::time::Duration::from_millis(100));
    Some((child, port))
}

struct MockServerGuard(Child);
impl Drop for MockServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn mock_url(port: u16) -> String {
    format!("http://127.0.0.1:{}/", port)
}

fn mock_dialog(port: u16) -> Dialog<New> {
    Dialog::new(
        &mock_url(port),
        &Blz::new("12345678"),
        &UserId::new("test1"),
        &Pin::new("1234"),
        &ProductId::new("TEST-123"),
    ).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests using the new protocol state machine
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_sync_dialog() {
    // Spec: sync dialog → get system_id + BPD + UPD → end
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    let dialog = mock_dialog(port);

    // Dialog<New> → sync() → Dialog<Synced>
    let (synced, response) = dialog.sync().await.expect("sync() failed");

    // System ID should be assigned (mock returns one via HISYN)
    assert!(synced.system_id().is_assigned(), "system_id should be assigned, got: {}", synced.system_id());

    // BPD should be populated
    assert!(synced.bank_params().bpd_version > 0, "BPD version should be > 0");
    assert!(!synced.bank_params().tan_methods.is_empty(), "Should have TAN methods");

    // UPD: should have accounts
    assert!(!synced.bank_params().accounts_from_upd.is_empty(), "Should have accounts from UPD");
    let has_test = synced.bank_params().accounts_from_upd.iter().any(|a| a.iban.as_str() == "DE11123456780000000001");
    assert!(has_test, "Should have test account DE11123456780000000001");

    // HIPINS: should know which ops need TAN
    assert!(!synced.bank_params().operation_tan_required.is_empty(), "HIPINS should be parsed");
    // Mock says HKSAL:N, HKKAZ:N — no TAN required
    assert_eq!(synced.bank_params().needs_tan(&SegmentType::new("HKSAL")), false, "HKSAL should not need TAN");
    assert_eq!(synced.bank_params().needs_tan(&SegmentType::new("HKKAZ")), false, "HKKAZ should not need TAN");

    // Response should have success code
    assert!(response.all_codes().any(|c| c.is_success()), "Should have success code");

    // Dialog<Synced> → end()
    let (params, sys_id) = synced.end().await.expect("end() failed");
    assert!(sys_id.is_assigned());
    assert!(params.bpd_version > 0);
}

#[tokio::test]
async fn test_init_no_tan_then_business_ops() {
    // Spec: init without HKTAN → Dialog<Open> → send business segments
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    // First sync to get params
    let sync_dialog = mock_dialog(port);
    let (synced, _) = sync_dialog.sync().await.expect("sync failed");
    let (params, sys_id) = synced.end().await.expect("end failed");

    // Open a new dialog with the params we got
    let dialog = mock_dialog(port)
        .with_system_id(&sys_id)
        .with_params(&params);

    // Dialog<New> → init_no_tan() → Dialog<Open>
    let (mut open, _resp) = dialog.init_no_tan().await.expect("init_no_tan failed");

    // Create a validated Account (BIC required!)
    let account = Account::new("DE11123456780000000001", "GENODE23X42").unwrap();

    // Dialog<Open> → balance(&account) → typed BalanceResult
    let result = open.balance(&account).await.expect("balance() failed");
    match result {
        BalanceResult::Success(balance) => {
            assert_eq!(balance.amount.to_string(), "1523.42");
            assert_eq!(balance.currency.as_str(), "EUR");
        }
        BalanceResult::NeedTan(_) => panic!("Unexpected TAN requirement"),
        BalanceResult::Empty => panic!("No balance data"),
    }

    // Dialog<Open> → end()
    open.end().await.expect("end failed");
}

#[tokio::test]
async fn test_transactions_with_pagination() {
    // Spec: HKKAZ → response with data + 3040 (touchdown) → HKKAZ(touchdown) → more data
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    // Sync + init
    let sync_dialog = mock_dialog(port);
    let (synced, _) = sync_dialog.sync().await.expect("sync failed");
    let (params, sys_id) = synced.end().await.expect("end failed");

    let dialog = mock_dialog(port).with_system_id(&sys_id).with_params(&params);
    let (mut open, _) = dialog.init_no_tan().await.expect("init failed");

    // Create a validated Account
    let account = Account::new("DE11123456780000000001", "GENODE23X42").unwrap();

    let start = chrono::NaiveDate::from_ymd_opt(2015, 1, 1).unwrap();
    let end_date = chrono::NaiveDate::from_ymd_opt(2015, 12, 31).unwrap();

    // Fetch transactions with pagination using typed API
    let mut all_mt940_booked: Vec<u8> = Vec::new();
    let mut touchdown: Option<fints::TouchdownPoint> = None;

    loop {
        let result = open.transactions(
            &account, start, end_date, touchdown.as_ref(),
        ).await.expect("transactions() failed");

        match result {
            TransactionResult::NeedTan(_) => panic!("Unexpected TAN requirement"),
            TransactionResult::Success(page) => {
                    if !page.booked.is_empty() {
                    if !all_mt940_booked.is_empty() { all_mt940_booked.extend_from_slice(b"\r\n"); }
                    all_mt940_booked.extend_from_slice(page.booked.as_bytes());
                }
                touchdown = page.touchdown;
                if touchdown.is_none() { break; }
            }
        }
    }

    // Parse MT940
    assert!(!all_mt940_booked.is_empty(), "Should have MT940 data");

    let (cow, _, _) = encoding_rs::WINDOWS_1252.decode(&all_mt940_booked);
    let cleaned: String = cow.lines()
        .filter(|l| { let t = l.trim(); !t.is_empty() && t != "-" && t != "--" })
        .collect::<Vec<_>>().join("\r\n") + "\r\n";
    let sanitized = mt940::sanitizers::to_swift_charset(&cleaned);
    let messages = mt940::parse_mt940(&sanitized).expect("MT940 parse failed");

    let tx_count: usize = messages.iter().map(|m| m.statement_lines.len()).sum();
    assert_eq!(tx_count, 3, "Expected 3 transactions across pagination, got {}", tx_count);

    let first = &messages[0].statement_lines[0];
    assert_eq!(first.amount.to_string(), "182.34");

    open.end().await.ok();
}

#[tokio::test]
async fn test_wrong_pin() {
    // Spec: wrong PIN → 9340/9910 error
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    let dialog = Dialog::new(
        &mock_url(port),
        &Blz::new("12345678"),
        &UserId::new("test1"),
        &Pin::new("wrong_pin"),
        &ProductId::new("TEST-123"),
    ).unwrap();

    let result = dialog.sync().await;
    assert!(result.is_err(), "sync() should fail with wrong PIN");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("PIN") || err.contains("9910") || err.contains("Bank error"),
        "Error should indicate PIN problem, got: {}", err
    );
}

#[tokio::test]
async fn test_sepa_accounts_from_upd() {
    // Spec: HIUPD in sync response → SEPA accounts
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    let dialog = mock_dialog(port);

    let (synced, _) = dialog.sync().await.expect("sync failed");
    let accounts = &synced.bank_params().accounts_from_upd;

    assert!(!accounts.is_empty(), "Should have at least one account from UPD");
    assert!(
        accounts.iter().any(|a| a.iban.as_str() == "DE11123456780000000001"),
        "Should have test account, got: {:?}",
        accounts.iter().map(|a| &a.iban).collect::<Vec<_>>()
    );

    synced.end().await.ok();
}

#[tokio::test]
async fn test_hipins_parsed() {
    // Spec: HIPINS → operation TAN requirements
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    let dialog = mock_dialog(port);

    let (synced, _) = dialog.sync().await.expect("sync failed");
    let params = synced.bank_params();

    // Mock HIPINS has HKSPA:N, HKKAZ:N, HKSAL:N, HKTAN:N
    assert!(!params.operation_tan_required.is_empty(), "HIPINS should be parsed");
    assert_eq!(params.needs_tan(&SegmentType::new("HKSAL")), false);
    assert_eq!(params.needs_tan(&SegmentType::new("HKKAZ")), false);
    assert_eq!(params.needs_tan(&SegmentType::new("HKSPA")), false);
    assert_eq!(params.needs_tan(&SegmentType::new("HKCCS")), true);

    synced.end().await.ok();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests using the Rust mock server (fints-server binary)
// ═══════════════════════════════════════════════════════════════════════════════

/// Helper: spawn the Rust mock server binary and return (child process, port).
fn spawn_rust_mock_server() -> Option<(std::process::Child, u16)> {
    let bin = assert_cmd::cargo::cargo_bin("fints-server");
    if !bin.exists() {
        return None;
    }

    let mut child = std::process::Command::new(&bin)
        .args(["--port", "0", "--print-ready", "--tan-mode", "none"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    use std::io::BufRead;
    let stdout = child.stdout.take()?;
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let port: u16 = line.trim().strip_prefix("READY:")?.parse().ok()?;
    std::thread::sleep(std::time::Duration::from_millis(100));
    Some((child, port))
}

#[tokio::test]
async fn test_rust_server_sync_dialog() {
    let (child, port) = match spawn_rust_mock_server() {
        Some(v) => v,
        None => {
            eprintln!("Skipping: fints-server not built");
            return;
        }
    };
    let _guard = MockServerGuard(child);

    let dialog = mock_dialog(port);
    let (synced, _) = dialog.sync().await.expect("sync failed against Rust server");
    assert!(synced.system_id().is_assigned());
    assert!(synced.bank_params().bpd_version > 0);
    synced.end().await.ok();
}

#[tokio::test]
async fn test_rust_server_balance() {
    let (child, port) = match spawn_rust_mock_server() {
        Some(v) => v,
        None => {
            eprintln!("Skipping: fints-server not built");
            return;
        }
    };
    let _guard = MockServerGuard(child);

    let sync_dialog = mock_dialog(port);
    let (synced, _) = sync_dialog.sync().await.expect("sync failed");
    let (params, sys_id) = synced.end().await.expect("end failed");

    let dialog = mock_dialog(port).with_system_id(&sys_id).with_params(&params);
    let (mut open, _) = dialog.init_no_tan().await.expect("init failed");

    let account = Account::new("DE11123456780000000001", "GENODE23X42").unwrap();
    let result = open.balance(&account).await.expect("balance failed");

    match result {
        BalanceResult::Success(balance) => {
            assert_eq!(balance.amount.to_string(), "1523.42");
        }
        _ => panic!("Expected balance success"),
    }
    open.end().await.ok();
}
