//! Tests for the high-level workflow, flow, dkb, and transport layers.
//!
//! Pure unit tests (registry dispatch, option helpers, account validation) run
//! without any network. End-to-end tests drive a `GenericBank` configured to
//! point at the Python mock FinTS server (`tests/mock_server.py`).

use std::io::BufRead;
use std::process::{Child, Command, Stdio};

use fints::protocol::{Account, BalanceResult};
use fints::{bank_ops, bank_ops_with_config, AnyBank, BankConfig, BankOps, Dkb, FetchOpts, Flow, Pin, ProductId, UserId};

// ═══════════════════════════════════════════════════════════════════════════
// Mock server helper
// ═══════════════════════════════════════════════════════════════════════════

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

/// A GenericBank whose FinTS endpoint points at the local mock server.
fn mock_any_bank(port: u16) -> AnyBank {
    bank_ops_with_config(BankConfig::new(
        "Test Bank",
        "12345678",
        "GENODE23X42",
        format!("http://127.0.0.1:{}/", port),
    ))
}

// ═══════════════════════════════════════════════════════════════════════════
// Pure unit tests (no network)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fetch_opts_helpers() {
    let all = FetchOpts::all(30);
    assert!(all.balance && all.transactions && all.holdings);
    assert_eq!(all.days, 30);

    let balance_only = FetchOpts::balance_only();
    assert!(balance_only.balance);
    assert!(!balance_only.transactions);
    assert!(!balance_only.holdings);
    assert_eq!(balance_only.days, 0);

    let no_holdings = FetchOpts::no_holdings(7);
    assert!(no_holdings.balance && no_holdings.transactions);
    assert!(!no_holdings.holdings);
    assert_eq!(no_holdings.days, 7);

    let default = FetchOpts::default();
    assert!(!default.balance && !default.transactions && !default.holdings);
    assert_eq!(default.days, 0);
}

#[test]
fn bank_ops_dispatch_dkb_blz() {
    let bank = bank_ops("12030000").expect("DKB BLZ should resolve");
    assert!(matches!(bank, AnyBank::Dkb(_)), "BLZ 12030000 must map to Dkb");
    assert_eq!(bank.config().blz.as_str(), "12030000");
}

#[test]
fn bank_ops_dispatch_generic_blz() {
    let bank = bank_ops("10070000").expect("known non-DKB BLZ should resolve");
    assert!(matches!(bank, AnyBank::Generic(_)), "BLZ 10070000 must map to GenericBank");
    assert_eq!(bank.config().blz.as_str(), "10070000");
}

#[test]
fn bank_ops_unknown_blz_is_error() {
    match bank_ops("99999999") {
        Ok(_) => panic!("expected error for unknown BLZ"),
        Err(e) => assert!(e.to_string().contains("Unknown BLZ"), "got: {}", e),
    }
}

#[test]
fn bank_ops_with_config_returns_generic() {
    let config = BankConfig::new("Custom", "12345678", "GENODE23X42", "https://example.invalid/fints");
    let bank = bank_ops_with_config(config.clone());
    assert!(matches!(bank, AnyBank::Generic(_)));
    assert_eq!(bank.config().blz.as_str(), "12345678");
    assert_eq!(bank.config().bic.as_str(), "GENODE23X42");
    assert_eq!(bank.config().url.as_str(), "https://example.invalid/fints");
}

#[test]
fn dkb_new_uses_registered_config() {
    let dkb = Dkb::new();
    assert_eq!(dkb.config().blz.as_str(), "12030000");
    assert_eq!(dkb.config().bic.as_str(), "BYLADEM1001");
    assert!(!dkb.config().url.as_str().is_empty());
}

#[test]
fn account_validation_requires_iban_and_bic() {
    assert!(Account::new("DE89370400440532013000", "COBADEFFXXX").is_ok());
    assert!(Account::new("", "COBADEFFXXX").is_err());
    assert!(Account::new("DE89370400440532013000", "").is_err());
}

#[test]
fn sync_result_serde_roundtrip() {
    use std::str::FromStr;
    use chrono::NaiveDate;
    use fints::flow::SyncResult;
    use fints::{AccountBalance, Bic, Currency, Iban, Transaction, TransactionStatus};
    use rust_decimal::Decimal;

    let txn = Transaction {
        date: NaiveDate::from_ymd_opt(2025, 1, 15).unwrap(),
        valuta_date: None,
        amount: Decimal::from_str("182.34").unwrap(),
        currency: Currency::new("EUR"),
        applicant_name: Some("Acme".to_string()),
        applicant_iban: Some(Iban::new("DE89370400440532013000")),
        applicant_bic: Some(Bic::new("COBADEFFXXX")),
        purpose: Some("Rechnung".to_string()),
        posting_text: None,
        reference: Some("REF-123".to_string()),
        raw: serde_json::json!({"date": "2025-01-15"}),
        status: TransactionStatus::Booked,
    };

    let result = SyncResult {
        iban: Iban::new("DE89370400440532013000"),
        bic: Bic::new("COBADEFFXXX"),
        balance: Some(AccountBalance {
            amount: Decimal::from_str("1523.42").unwrap(),
            date: NaiveDate::from_ymd_opt(2025, 1, 15).unwrap(),
            currency: Currency::new("EUR"),
            credit_line: None,
            available: None,
            pending_amount: None,
            pending_date: None,
        }),
        transactions: vec![txn],
        holdings: vec![],
        system_id: None,
    };

    let json = serde_json::to_string(&result).expect("serialize");
    let back: SyncResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.iban.as_str(), "DE89370400440532013000");
    assert_eq!(back.transactions.len(), 1);
    let bal = back.balance.unwrap();
    assert_eq!(bal.amount.to_string(), "1523.42");
    assert_eq!(bal.currency.as_str(), "EUR");
}

#[test]
fn currency_conversion_and_display() {
    use fints::Currency;
    let eur = Currency::new("EUR");
    assert_eq!(eur.as_str(), "EUR");
    assert_eq!(eur.to_string(), "EUR");
}

// ═══════════════════════════════════════════════════════════════════════════
// End-to-end tests (GenericBank → mock FinTS server)
// ═══════════════════════════════════════════════════════════════════════════

fn test_credentials() -> (UserId, Pin, ProductId) {
    (
        UserId::new("test1"),
        Pin::new("1234"),
        ProductId::new("TEST-123"),
    )
}

#[tokio::test]
async fn flow_connect_then_confirm_and_fetch() {
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    let (user, pin, product) = test_credentials();
    let bank = mock_any_bank(port);

    // Step 1: initiate → should be SCA-exempt with the mock (no TAN).
    let (mut flow, info) = Flow::initiate_with_bank(
        bank, &user, &pin, &product, None, None, None,
    ).await.expect("initiate_with_bank failed");

    assert!(info.no_tan_required, "mock server should not require TAN on init");
    assert!(!flow.system_id().as_str().is_empty(), "system_id should be assigned");

    // Step 2: fetch everything.
    let result = flow.confirm_and_fetch("DE11123456780000000001", "GENODE23X42", 365)
        .await.expect("confirm_and_fetch failed");

    let balance = result.balance.expect("balance should be present");
    assert_eq!(balance.amount.to_string(), "1523.42");
    assert_eq!(balance.currency.as_str(), "EUR");

    // Mock returns 2 MT940 pages with 3 transaction lines.
    assert_eq!(result.transactions.len(), 3, "expected 3 transactions, got {:?}", result.transactions);
    assert_eq!(result.iban.as_str(), "DE11123456780000000001");
    assert_eq!(result.bic.as_str(), "GENODE23X42");
    assert!(result.system_id.is_some(), "system_id should be returned");
}

#[tokio::test]
async fn flow_reusing_confirm_twice_fails() {
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    let (user, pin, product) = test_credentials();
    let mut flow = Flow::initiate_with_bank(
        mock_any_bank(port), &user, &pin, &product, None, None, None,
    ).await.expect("initiate failed").0;

    flow.confirm_and_fetch("DE11123456780000000001", "GENODE23X42", 30)
        .await.expect("first fetch should succeed");

    let err = flow.confirm_and_fetch("DE11123456780000000001", "GENODE23X42", 30)
        .await.expect_err("second fetch should fail (flow already completed)");
    assert!(err.to_string().contains("already completed"), "got: {}", err);
}

#[tokio::test]
async fn flow_fetch_balance_only() {
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    let (user, pin, product) = test_credentials();
    let mut flow = Flow::initiate_with_bank(
        mock_any_bank(port), &user, &pin, &product, None, None, None,
    ).await.expect("initiate failed").0;

    let result = flow.confirm_and_fetch_opts("DE11123456780000000001", "GENODE23X42", &FetchOpts::balance_only())
        .await.expect("balance-only fetch failed");

    assert!(result.balance.is_some(), "should have fetched balance");
    assert!(result.transactions.is_empty(), "transactions should be skipped with balance_only");
    assert!(result.holdings.is_empty(), "holdings should be skipped with balance_only");
}

#[tokio::test]
async fn flow_fetch_holdings_via_mock() {
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    let (user, pin, product) = test_credentials();
    let mut flow = Flow::initiate_with_bank(
        mock_any_bank(port), &user, &pin, &product, None, None, None,
    ).await.expect("initiate failed").0;

    // The mock server does not answer HKWPD → expect an empty holdings list.
    let holdings = flow.confirm_and_fetch_holdings("DE11123456780000000001", "GENODE23X42")
        .await.expect("fetch holdings should not fail against mock");
    assert!(holdings.is_empty(), "mock has no depot data");
}

#[tokio::test]
async fn flow_initiate_with_unknown_bank_fails() {
    match Flow::initiate("99999999", &UserId::new("x"), &Pin::new("1"), &ProductId::new("p"), None, None, None).await {
        Ok(_) => panic!("expected error for unknown BLZ"),
        Err(e) => assert!(e.to_string().contains("Unknown BLZ"), "got: {}", e),
    }
}

#[tokio::test]
async fn flow_bic_fallback_to_bank_config() {
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    let (user, pin, product) = test_credentials();
    let mut flow = Flow::initiate_with_bank(
        mock_any_bank(port), &user, &pin, &product, None, None, None,
    ).await.expect("initiate failed").0;

    // Providing an empty BIC falls back to the bank config BIC (GENODE23X42),
    // so the authenticated fetch still succeeds against the mock server.
    let result = flow.confirm_and_fetch("DE11123456780000000001", "", 30)
        .await.expect("fetch with fallback BIC failed");
    assert!(result.balance.is_some(), "balance should be fetched despite empty BIC");
    assert_eq!(result.transactions.len(), 3);
}

#[tokio::test]
async fn generic_bank_direct_balance() {
    // Exercise the BankOps::fetch path directly via a GenericBank held in AnyBank.
    let (child, port) = match spawn_mock_server() {
        Some(v) => v,
        None => { eprintln!("Skipping: python3 not available"); return; }
    };
    let _guard = MockServerGuard(child);

    let (user, pin, product) = test_credentials();
    let bank = mock_any_bank(port);

    match bank.initiate(&user, &pin, &product, None, None, None).await.expect("initiate") {
        fints::InitiateOutcome::Authenticated(mut result) => {
            let account = Account::new("DE11123456780000000001", "GENODE23X42").unwrap();
            let fetch = bank.fetch(&mut result.dialog, &account, 30).await.expect("fetch failed");
            assert_eq!(fetch.balance.as_ref().map(|b| b.amount.to_string()), Some("1523.42".to_string()));
            assert_eq!(fetch.transactions.len(), 3, "expected 3 transactions");
            result.dialog.end().await.ok();
        }
        fints::InitiateOutcome::NeedTan(_) => panic!("mock should open directly"),
    }

    // Directly exercise BalanceResult typing on an authenticated dialog.
    match bank.initiate(&user, &pin, &product, None, None, None).await.expect("initiate") {
        fints::InitiateOutcome::Authenticated(result) => {
            let mut dialog = result.dialog;
            let account = Account::new("DE11123456780000000001", "GENODE23X42").unwrap();
            match dialog.balance(&account).await.expect("balance") {
                BalanceResult::Success(bal) => assert_eq!(bal.amount.to_string(), "1523.42"),
                _ => panic!("expected balance success"),
            }
            dialog.end().await.ok();
        }
        fints::InitiateOutcome::NeedTan(_) => panic!("mock should open directly"),
    }
}
