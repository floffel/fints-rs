//! FinTS 3.0 Mock Server
//!
//! A full FinTS 3.0 mock server for testing and development.
//! Replaces the Python mock_server.py with a native Rust implementation.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin fints-server --features server -- --port 3000
//! cargo run --bin fints-server --features server -- --port 0 --print-ready
//! ```

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Parser, ValueEnum};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::Mutex,
    time::Instant,
};
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Parser, Debug)]
#[command(name = "fints-server", about = "FinTS 3.0 mock server for testing and development")]
struct Cli {
    /// Port to listen on (0 = random)
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// TAN mode: decoupled, sms, none
    #[arg(long, default_value = "decoupled")]
    tan_mode: TanMode,

    /// Auto-confirm decoupled TAN after N seconds (0 = manual/never)
    #[arg(long, default_value = "3")]
    auto_confirm_secs: u64,

    /// Inject error on this operation (balance, transactions, holdings, init)
    #[arg(long)]
    error_on: Option<ErrorOn>,

    /// Error type to inject (wrong-pin, locked, bank-error, timeout)
    #[arg(long, default_value = "bank-error")]
    error_type: ErrorType,

    /// Fixtures directory (JSON files for accounts, balances, transactions)
    #[arg(long)]
    fixtures: Option<PathBuf>,

    /// Verbose: log decoded segments
    #[arg(short, long)]
    verbose: bool,

    /// Debug wire: log full hex dumps
    #[arg(long)]
    debug_wire: bool,

    /// Audit mode: validate all client messages for spec compliance
    #[arg(long)]
    audit: bool,

    /// Write audit log to this file (JSON)
    #[arg(long)]
    audit_log: Option<PathBuf>,

    /// Simulate network latency in milliseconds
    #[arg(long, default_value = "0")]
    latency_ms: u64,

    /// Print server address on startup (for test harness integration)
    #[arg(long)]
    print_ready: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TanMode {
    Decoupled,
    Sms,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ErrorOn {
    Balance,
    Transactions,
    Holdings,
    Init,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ErrorType {
    WrongPin,
    Locked,
    BankError,
    Timeout,
}

// ═══════════════════════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug)]
struct ServerState {
    config: ServerConfig,
    dialogs: HashMap<String, DialogState>,
    systems: HashMap<String, SystemInfo>,
    dialog_counter: u32,
    system_counter: u32,
    dialog_prefix: String,
    system_prefix: String,
    port: u16,
}

#[derive(Debug)]
struct DialogState {
    dialog_id: String,
    message_count: u32,
    tan_state: TanState,
}

#[derive(Debug)]
#[allow(dead_code)]
enum TanState {
    None,
    Pending { confirmed_at: Option<Instant> },
    Confirmed,
}

#[derive(Debug)]
struct SystemInfo {
    #[allow(dead_code)]
    system_id: String,
}

#[derive(Debug)]
struct ServerConfig {
    tan_mode: TanMode,
    auto_confirm_secs: u64,
    error_on: Option<ErrorOn>,
    #[allow(dead_code)]
    error_type: ErrorType,
    fixtures: Fixtures,
    verbose: bool,
    debug_wire: bool,
    latency_ms: u64,
}

#[derive(Debug)]
struct Fixtures {
    accounts: Vec<MockAccount>,
    holdings: Vec<MockHolding>,
    valid_pins: Vec<String>,
    temp_locked_pins: Vec<String>,
}

#[derive(Debug, Clone)]
struct MockAccount {
    iban: String,
    #[allow(dead_code)]
    bic: String,
    blz: String,
    #[allow(dead_code)]
    owner: String,
    product_name: String,
    currency: String,
    balance: String,
    balance_date: String,
    account_number: String,
}

/// A mock securities holding position for HIWPD responses.
#[derive(Debug, Clone)]
struct MockHolding {
    /// ISIN (12 chars)
    isin: String,
    /// WKN (6 chars)
    wkn: String,
    /// Security name
    name: String,
    /// Number of units/shares (FinTS comma decimal, e.g. "100,000")
    quantity: String,
    /// Price per unit (FinTS comma decimal)
    price: String,
    /// Price currency (ISO 4217)
    price_currency: String,
    /// Price date (YYYYMMDD)
    price_date: String,
    /// Total market value (quantity * price, FinTS comma decimal)
    market_value: String,
}

impl Default for Fixtures {
    fn default() -> Self {
        Self {
            valid_pins: vec!["1234".to_string()],
            temp_locked_pins: vec!["3938".to_string()],
            accounts: vec![
                MockAccount {
                    // Valid German IBAN (22 chars, passes checksum)
                    iban: "DE89370400440532013000".to_string(),
                    bic: "GENODE23X42".to_string(),
                    blz: "12345678".to_string(),
                    owner: "Fullname".to_string(),
                    product_name: "Girokonto".to_string(),
                    currency: "EUR".to_string(),
                    balance: "1523,42".to_string(),
                    balance_date: "20250115".to_string(),
                    account_number: "0532013000".to_string(),
                },
                MockAccount {
                    // Valid German IBAN (22 chars, passes checksum)
                    iban: "DE75200400600526370400".to_string(),
                    bic: "GENODE23X42".to_string(),
                    blz: "12345678".to_string(),
                    owner: "Fullname".to_string(),
                    product_name: "Tagesgeld".to_string(),
                    currency: "EUR".to_string(),
                    balance: "9876,54".to_string(),
                    balance_date: "20250115".to_string(),
                    account_number: "0526370400".to_string(),
                },
            ],
            holdings: vec![
                MockHolding {
                    isin: "DE0005140008".to_string(),
                    wkn: "514000".to_string(),
                    name: "DEUTSCHE BANK AG".to_string(),
                    quantity: "100,000".to_string(),
                    price: "14,20".to_string(),
                    price_currency: "EUR".to_string(),
                    price_date: "20260330".to_string(),
                    market_value: "1420,00".to_string(),
                },
                MockHolding {
                    isin: "US0378331005".to_string(),
                    wkn: "865985".to_string(),
                    name: "APPLE INC".to_string(),
                    quantity: "10,000".to_string(),
                    price: "172,50".to_string(),
                    price_currency: "USD".to_string(),
                    price_date: "20260330".to_string(),
                    market_value: "1725,00".to_string(),
                },
                MockHolding {
                    isin: "IE00B4L5Y983".to_string(),
                    wkn: "A0RPWH".to_string(),
                    name: "ISHARES CORE MSCI WORLD ETF".to_string(),
                    quantity: "25,000".to_string(),
                    price: "98,34".to_string(),
                    price_currency: "EUR".to_string(),
                    price_date: "20260330".to_string(),
                    market_value: "2458,50".to_string(),
                },
            ],
        }
    }
}

type SharedState = Arc<Mutex<ServerState>>;

// ═══════════════════════════════════════════════════════════════════════════════
// Transactions data (matches Python mock exactly)
// ═══════════════════════════════════════════════════════════════════════════════

fn build_transaction_pages() -> Vec<Vec<u8>> {
    // Two pages of MT940 transactions matching the Python mock
    let page0: Vec<&[u8]> = vec![
        b"-",
        b":20:STARTUMS",
        b":25:12345678/0000000001",
        b":28C:0",
        b":60F:C150101EUR1041,23",
        b":61:150101C182,34NMSCNONREF",
        b":86:051?00UEBERWEISG?10931?20Ihre Kontonummer 0000001234",
        b"?21/Test Ueberweisung 1?22n WS EREF: 1100011011 IBAN:",
        b"?23 DE1100000100000001234 BIC?24: GENODE11 ?1011010100",
        b"?31?32Bank",
        b":62F:C150101EUR1223,57",
        b"-",
    ];

    let page1: Vec<&[u8]> = vec![
        b"-",
        b":20:STARTUMS",
        b":25:12345678/0000000001",
        b":28C:0",
        b":60F:C150301EUR1223,57",
        b":61:150301C100,03NMSCNONREF",
        b":86:051?00UEBERWEISG?10931?20Ihre Kontonummer 0000001234",
        b"?21/Test Ueberweisung 2?22n WS EREF: 1100011011 IBAN:",
        b"?23 DE1100000100000001234 BIC?24: GENODE11 ?1011010100",
        b"?31?32Bank",
        b":61:150301C100,00NMSCNONREF",
        b":86:051?00UEBERWEISG?10931?20Ihre Kontonummer 0000001234",
        b"?21/Test Ueberweisung 3?22n WS EREF: 1100011011 IBAN:",
        b"?23 DE1100000100000001234 BIC?24: GENODE11 ?1011010100",
        b"?31?32Bank",
        b":62F:C150101EUR1423,60",
        b"-",
    ];

    vec![
        build_mt940_block(&page0),
        build_mt940_block(&page1),
    ]
}

fn build_mt940_block(lines: &[&[u8]]) -> Vec<u8> {
    // Join with CRLF, leading and trailing CRLF
    let mut result = Vec::new();
    result.extend_from_slice(b"\r\n");
    for (i, line) in lines.iter().enumerate() {
        result.extend_from_slice(line);
        if i + 1 < lines.len() {
            result.extend_from_slice(b"\r\n");
        }
    }
    result.extend_from_slice(b"\r\n");
    result
}

// ═══════════════════════════════════════════════════════════════════════════════
// Message parsing helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Extract the HNHBK dialog_id from a raw message
fn extract_dialog_id(message: &[u8]) -> Option<String> {
    // HNHBK:1:3+{size}+300+{dialog_id}+{msg_num}'
    let msg = std::str::from_utf8(message).ok()?;
    let start = msg.find("HNHBK:1:3+")?;
    let after = &msg[start + "HNHBK:1:3+".len()..];
    // skip size field
    let plus1 = after.find('+')?;
    let after = &after[plus1 + 1..];
    // skip version field (300)
    let plus2 = after.find('+')?;
    let after = &after[plus2 + 1..];
    // dialog_id is up to next +
    let plus3 = after.find('+')?;
    Some(after[..plus3].to_string())
}

/// Extract the HNVSD inner data (binary payload)
fn extract_hnvsd(message: &[u8]) -> Option<Vec<u8>> {
    // Find HNVSD:999:1+@N@<data>'
    let marker = b"HNVSD:999:1+";
    let pos = message.windows(marker.len()).position(|w| w == marker)?;
    let after = &message[pos + marker.len()..];

    if after.first() != Some(&b'@') {
        return None;
    }
    let after = &after[1..];
    let end_at = after.iter().position(|&b| b == b'@')?;
    let len_str = std::str::from_utf8(&after[..end_at]).ok()?;
    let bin_len: usize = len_str.parse().ok()?;
    let data_start = end_at + 1;
    if data_start + bin_len > after.len() {
        return None;
    }
    Some(after[data_start..data_start + bin_len].to_vec())
}

/// Extract PIN from HNSHA segment in message bytes
fn extract_pin_tan(message: &[u8]) -> (Option<String>, Option<String>) {
    // HNSHA:\d+:\d+\+[^+]*\+[^+]*\+<pin>[:<tan>]'
    // Try to find HNSHA in both outer and inner (HNVSD) data
    let search_in = if let Some(inner) = extract_hnvsd(message) {
        inner
    } else {
        message.to_vec()
    };

    let pattern = b"HNSHA:";
    let mut pin = None;
    let mut tan = None;

    if let Some(pos) = search_in.windows(pattern.len()).position(|w| w == pattern) {
        let seg = &search_in[pos..];
        // HNSHA format: HNSHA:<seg>:2+<security_ref>+<validation>+<pin>[:<tan>]'
        // The PIN is after the 3rd '+' (DEGs: header, security_ref, validation, user_sig)
        let mut plus_count = 0;
        let mut i = 0;
        while i < seg.len() {
            match seg[i] {
                b'+' => {
                    plus_count += 1;
                    if plus_count == 3 {
                        // PIN:TAN field starts at i+1
                        let pin_tan_start = i + 1;
                        // Field ends at segment terminator '\'' (not at another '+' since PIN may have none)
                        let end = seg[pin_tan_start..].iter()
                            .position(|&b| b == b'\'')
                            .map(|p| pin_tan_start + p)
                            .unwrap_or(seg.len());
                        let pin_tan = &seg[pin_tan_start..end];
                        // Check if there's a colon separating PIN from TAN
                        if let Some(colon_pos) = pin_tan.iter().position(|&b| b == b':') {
                            pin = std::str::from_utf8(&pin_tan[..colon_pos]).ok().map(|s| s.to_string());
                            if colon_pos + 1 < pin_tan.len() {
                                tan = std::str::from_utf8(&pin_tan[colon_pos + 1..]).ok().map(|s| s.to_string());
                            }
                        } else {
                            pin = std::str::from_utf8(pin_tan).ok().map(|s| s.to_string());
                        }
                        break;
                    }
                    i += 1;
                }
                b'\'' => break,
                _ => {
                    i += 1;
                }
            }
        }
    }

    (pin, tan)
}

/// Check if a segment type is present in message
fn has_segment(message: &[u8], seg_type: &str) -> bool {
    let needle = format!("{}:", seg_type);
    message.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// Extract segment number and version for a given segment type
fn extract_seg_num_ver(message: &[u8], seg_type: &str) -> Option<(String, String)> {
    let prefix = format!("{}:", seg_type);
    let pos = message.windows(prefix.len()).position(|w| w == prefix.as_bytes())?;
    let after = &message[pos + prefix.len()..];
    // Next is segno:version
    let colon1 = after.iter().position(|&b| b == b':')?;
    let segno = std::str::from_utf8(&after[..colon1]).ok()?.to_string();
    let after2 = &after[colon1 + 1..];
    let end = after2.iter().position(|&b| b == b'+' || b == b':' || b == b'\'')?;
    let version = std::str::from_utf8(&after2[..end]).ok()?.to_string();
    Some((segno, version))
}

/// Extract HKVVB BPD and UPD versions
fn extract_hkvvb_versions(message: &[u8]) -> Option<(String, String)> {
    // HKVVB:\d+:3+{bpd_ver}+{upd_ver}+...
    let prefix = b"HKVVB:";
    let pos = message.windows(prefix.len()).position(|w| w == prefix)?;
    let after = &message[pos + prefix.len()..];
    // Skip seg_num:version+
    let plus1 = after.iter().position(|&b| b == b'+')?;
    let after = &after[plus1 + 1..];
    // bpd version
    let plus2 = after.iter().position(|&b| b == b'+')?;
    let bpd = std::str::from_utf8(&after[..plus2]).ok()?.to_string();
    let after = &after[plus2 + 1..];
    // upd version
    let plus3 = after.iter().position(|&b| b == b'+' || b == b'\'')?;
    let upd = std::str::from_utf8(&after[..plus3]).ok()?.to_string();
    Some((bpd, upd))
}

/// Extract touchdown point from HKKAZ request
fn extract_hkkaz_touchdown(message: &[u8]) -> Option<u32> {
    // HKKAZ:N:M+account+N+from+to+max+touchdown'
    // The Python mock: hkkaz.group(3) is the 3rd optional capture after N+...
    // Pattern: HKKAZ:\d+:\d++[^+]++N(?:+[^+]*+[^+]*(?:+[^+]*+([^+']*)))?'
    let prefix = b"HKKAZ:";
    let pos = message.windows(prefix.len()).position(|w| w == prefix)?;
    let seg_data = &message[pos..];
    // Find end of segment
    let end = seg_data.iter().position(|&b| b == b'\'')?;
    let seg = &seg_data[..end];
    let seg_str = std::str::from_utf8(seg).ok()?;

    // Split by '+' to get fields
    let parts: Vec<&str> = seg_str.split('+').collect();
    // parts[0] = "HKKAZ:segno:version"
    // parts[1] = account (KTV)
    // parts[2] = "N" (all accounts flag)
    // parts[3] = from date (optional)
    // parts[4] = to date (optional)
    // parts[5] = max entries (optional)
    // parts[6] = touchdown (optional)
    if parts.len() > 6 {
        let td = parts[6].trim();
        if !td.is_empty() {
            return td.parse::<u32>().ok();
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════
// Response building
// ═══════════════════════════════════════════════════════════════════════════════

fn build_envelope(dialog_id: &str, msg_num: u32, inner: &[u8]) -> Vec<u8> {
    let inner_len = inner.len();
    let inner_bin = format!("@{}@", inner_len);

    let hnvsk = "HNVSK:998:3+PIN:1+998+1+2::0+1+2:2:13:@8@\x00\x00\x00\x00\x00\x00\x00\x00:5:1+280:12345678:0:S:0:0+0'";
    let hnvsd_prefix = "HNVSD:999:1+";
    let hnhbs = format!("HNHBS:5:1+{}'", msg_num);

    // Build body (everything after HNHBK)
    let mut body = Vec::new();
    body.extend_from_slice(hnvsk.as_bytes());
    body.extend_from_slice(hnvsd_prefix.as_bytes());
    body.extend_from_slice(inner_bin.as_bytes());
    body.extend_from_slice(inner);
    body.extend_from_slice(b"'");
    body.extend_from_slice(hnhbs.as_bytes());

    // Header template: HNHBK:1:3+NNNNNNNNNNNN+300+dialog_id+msg_num'
    // Compute with placeholder size (0)
    let header_test = format!("HNHBK:1:3+{:012}+300+{}+{}'", 0, dialog_id, msg_num);
    let total = header_test.len() + body.len();
    let header = format!("HNHBK:1:3+{:012}+300+{}+{}'", total, dialog_id, msg_num);

    let mut result = Vec::new();
    result.extend_from_slice(header.as_bytes());
    result.extend_from_slice(&body);
    result
}

fn build_bpd(port: u16) -> String {
    format!(
        "HIBPA:6:3:4+78+280:12345678+Test Bank+1+1+300+500'\
HIKOM:7:4:4+280:12345678+1+3:http?://127.0.0.1?:{port}/'\
HIKAZS:10:7:4+1+1+1+365:J:N'\
HISPAS:31:1:4+1+1+1+J:J:N:sepade?:xsd?:pain.001.003.03.xsd'\
HISALS:19:7:4+1+1+1'\
HIWPDS:20:6:4+1+1+1'\
HITANS:53:7:4+1+1+1+N:N:0:942:2:MTAN2:mobileTAN::mobile TAN:6:1:SMS:3:1:J:1:0:N:0:2:N:J:00:1:1:962:2:HHD1.4:HHD:1.4:Smart-TAN plus manuell:6:1:Challenge:3:1:J:1:0:N:0:2:N:J:00:1:1'\
HIPINS:54:1:4+1+1+1+5:20:6:Benutzer ID::HKSPA:N:HKKAZ:N:HKSAL:N:HKTAN:N'",
        port = port
    )
}

fn build_upd() -> &'static str {
    "HIUPA:57:4:4+test1+3+0'\
HIUPD:58:6:4+1::280:12345678+DE11123456780000000001+GENODE23X42+test1+EUR+Fullname++Girokonto++HKSAL:1+HKKAZ:1+HKSPA:1'\
HIUPD:59:6:4+2::280:12345678+DE11123456780000000002+GENODE23X42+test1+EUR+Fullname++Tagesgeld++HKSAL:1+HKKAZ:1+HKSPA:1'"
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main handler logic
// ═══════════════════════════════════════════════════════════════════════════════

async fn make_answer(
    state: &mut ServerState,
    _dialog_id: &str,
    message: &[u8],
) -> Vec<u8> {
    // Get the inner message (from HNVSD or the raw message if it's a simple error)
    let _inner_message = extract_hnvsd(message).unwrap_or_else(|| message.to_vec());

    // Extract PIN
    let (pin_opt, _tan_opt) = extract_pin_tan(message);
    let pin = pin_opt.as_deref().unwrap_or("");

    let is_valid_pin = state.config.fixtures.valid_pins.iter().any(|p| p == pin);
    let is_temp_locked = state.config.fixtures.temp_locked_pins.iter().any(|p| p == pin);

    if !is_valid_pin && !is_temp_locked {
        // Wrong PIN — return error immediately (no envelope yet, just inner)
        return b"HIRMG::2+9910::Pin ung\xc3\xbcltig'".to_vec();
    }

    let mut result: Vec<u8> = Vec::new();
    result.extend_from_slice(b"HIRMG::2+0010::Nachricht entgegengenommen'");

    // Handle HKVVB — BPD/UPD response
    if let Some((bpd_ver, upd_ver)) = extract_hkvvb_versions(message) {
        let hkvvb_segno = extract_seg_num_ver(message, "HKVVB")
            .map(|(n, _)| n)
            .unwrap_or_else(|| "3".to_string());

        let mut responses: Vec<Vec<u8>> = vec![hkvvb_segno.as_bytes().to_vec()];
        let mut segments: Vec<Vec<u8>> = Vec::new();

        if bpd_ver != "78" {
            responses.push(b"3050::BPD nicht mehr aktuell, aktuelle Version enthalten.".to_vec());
            segments.push(build_bpd(state.port).into_bytes());
        }

        if upd_ver != "3" {
            responses.push(b"3050::UPD nicht mehr aktuell, aktuelle Version enthalten.".to_vec());
            segments.push(build_upd().as_bytes().to_vec());
        }

        if is_temp_locked {
            let msg = "3938::Ihr Zugang ist vor\u{00fc}bergehend gesperrt.";
            responses.push(msg.as_bytes().to_vec());
        } else {
            responses.push(b"3920::Zugelassene TAN-Verfahren fur den Benutzer:942".to_vec());
            responses.push(b"0901::*PIN gultig.".to_vec());
        }
        responses.push(b"0020::*Dialoginitialisierung erfolgreich".to_vec());

        // Build HIRMS
        let hirms = {
            let mut r = b"HIRMS::2:".to_vec();
            r.extend_from_slice(&responses.join(&b'+'));
            r.extend_from_slice(b"'");
            r
        };
        result.extend_from_slice(&hirms);
        for seg in &segments {
            result.extend_from_slice(seg);
        }
    }

    // Handle HKSYN — synchronization
    if has_segment(message, "HKSYN") {
        let system_id = {
            let count = state.system_counter + 1;
            state.system_counter = count;
            format!("{};{:05}", state.system_prefix, count)
        };
        state.systems.insert(system_id.clone(), SystemInfo { system_id: system_id.clone() });
        let hisyn = format!("HISYN::4:5+{}'", system_id);
        result.extend_from_slice(hisyn.as_bytes());
    }

    // Handle HKSPA — SEPA account list
    if has_segment(message, "HKSPA") {
        result.extend_from_slice(
            b"HISPA::1:4+J:DE11123456780000000001:GENODE23X42:00001::280:12345678'"
        );
    }

    // Handle HKSAL — balance
    if let Some((segno, _)) = extract_seg_num_ver(message, "HKSAL") {
        let balance = state.config.fixtures.accounts.first()
            .map(|a| (a.balance.clone(), a.currency.clone(), a.balance_date.clone()))
            .unwrap_or_else(|| ("1523,42".to_string(), "EUR".to_string(), "20250115".to_string()));

        let hirms = format!("HIRMS::2:{segno}+0010::Saldo ermittelt'", segno = segno);
        let hisal = format!(
            "HISAL::7:{segno}+1::280:12345678+Girokonto+{currency}+C:{balance}:{currency}:{date}'",
            segno = segno,
            balance = balance.0,
            currency = balance.1,
            date = balance.2,
        );
        result.extend_from_slice(hirms.as_bytes());
        result.extend_from_slice(hisal.as_bytes());
    }

    // Handle HKKAZ — transactions with pagination
    if let Some((segno, _)) = extract_seg_num_ver(message, "HKKAZ") {
        let startat = extract_hkkaz_touchdown(message).unwrap_or(0) as usize;
        let transactions = build_transaction_pages();

        if startat + 1 < transactions.len() {
            let hirms = format!(
                "HIRMS::2:{segno}+3040::Es liegen weitere Informationen vor:{next}'",
                segno = segno,
                next = startat + 1,
            );
            result.extend_from_slice(hirms.as_bytes());
        } else {
            let hirms = format!(
                "HIRMS::2:{segno}+0010::Umsaetze geliefert'",
                segno = segno,
            );
            result.extend_from_slice(hirms.as_bytes());
        }

        let tx = &transactions[startat.min(transactions.len() - 1)];
        let hikaz_prefix = format!(
            "HIKAZ::7:{segno}+@{len}@",
            segno = segno,
            len = tx.len(),
        );
        result.extend_from_slice(hikaz_prefix.as_bytes());
        result.extend_from_slice(tx);
        result.extend_from_slice(b"'");
    }

    // Handle HKWPD — securities holdings
    if let Some((segno, _)) = extract_seg_num_ver(message, "HKWPD") {
        let hirms = format!("HIRMS::2:{segno}+0010::Depot abgerufen'", segno = segno);
        result.extend_from_slice(hirms.as_bytes());

        if state.config.fixtures.holdings.is_empty() {
            // No holdings — empty response
            let hiwpd = format!("HIWPD::6:{segno}+DE89370400440532013000:GENODE23X42'", segno = segno);
            result.extend_from_slice(hiwpd.as_bytes());
        } else {
            // Build HIWPD segment with holding positions as DEGs
            // Format: HIWPD:<seg>:6:<ref>+<IBAN>:<BIC>[+<ISIN>:<WKN>:<name>:<qty>:<price>:<currency>:<date>:<market_value>]*'
            // Use account from fixtures (first account IBAN:BIC)
            let account_deg = {
                let acc = state.config.fixtures.accounts.first();
                match acc {
                    Some(a) => format!("{}:{}", a.iban, a.bic),
                    None => "DE89370400440532013000:GENODE23X42".to_string(),
                }
            };
            let mut hiwpd = format!("HIWPD::6:{segno}+{account}", segno = segno, account = account_deg);
            for h in &state.config.fixtures.holdings {
                // Escape FinTS special chars in name (? for +, :, ', @, ?)
                let safe_name = h.name
                    .replace('?', "??")
                    .replace('+', "?+")
                    .replace(':', "?:")
                    .replace('\'', "?'")
                    .replace('@', "?@");
                hiwpd.push_str(&format!(
                    "+{}:{}:{}:{}:{}:{}:{}:{}",
                    h.isin, h.wkn, safe_name,
                    h.quantity, h.price, h.price_currency, h.price_date,
                    h.market_value,
                ));
            }
            hiwpd.push('\'');
            result.extend_from_slice(hiwpd.as_bytes());
        }
    }

    // Handle HKTAN — TAN processing (just acknowledge)
    if has_segment(message, "HKTAN") {
        // Silently accept per Python mock
    }

    // Handle HKEND — dialog end
    if has_segment(message, "HKEND") {
        result.extend_from_slice(b"HIRMS::2+0010::Dialog beendet'");
    }

    result
}

async fn handle_fints_request(
    State(state): State<SharedState>,
    body: Bytes,
) -> impl IntoResponse {
    // Decode base64 request
    let message = match BASE64.decode(&body) {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to decode base64 request: {}", e);
            return (StatusCode::BAD_REQUEST, Bytes::new());
        }
    };

    let locked = state.lock().await;

    if locked.config.verbose {
        info!("[wire] REQUEST ({} bytes): {}", message.len(),
            String::from_utf8_lossy(&message).chars().take(300).collect::<String>());
    }
    if locked.config.debug_wire {
        info!("[wire] REQUEST HEX: {}", hex_dump(&message));
    }

    // Simulate latency
    let latency = locked.config.latency_ms;
    drop(locked); // release lock during sleep

    if latency > 0 {
        tokio::time::sleep(Duration::from_millis(latency)).await;
    }

    let mut locked = state.lock().await;

    // Extract dialog ID
    let dialog_id_raw = extract_dialog_id(&message).unwrap_or_else(|| "0".to_string());

    let dialog_id = if dialog_id_raw == "0" {
        // New dialog — create ID
        let count = locked.dialog_counter + 1;
        locked.dialog_counter = count;
        let new_id = format!("{};{:05}", locked.dialog_prefix, count);
        locked.dialogs.insert(new_id.clone(), DialogState {
            dialog_id: new_id.clone(),
            message_count: 0,
            tan_state: TanState::None,
        });
        new_id
    } else {
        // Existing dialog
        if !locked.dialogs.contains_key(&dialog_id_raw) {
            // Auto-create if missing (for robustness)
            locked.dialogs.insert(dialog_id_raw.clone(), DialogState {
                dialog_id: dialog_id_raw.clone(),
                message_count: 0,
                tan_state: TanState::None,
            });
        }
        dialog_id_raw
    };

    // Increment message count
    let msg_num = {
        let d = locked.dialogs.get_mut(&dialog_id).unwrap();
        d.message_count += 1;
        d.message_count
    };

    // Build response inner
    let inner = make_answer(&mut locked, &dialog_id, &message).await;

    if locked.config.verbose {
        info!("[wire] INNER RESPONSE ({} bytes): {}", inner.len(),
            String::from_utf8_lossy(&inner).chars().take(300).collect::<String>());
    }

    // Wrap in envelope
    let response = build_envelope(&dialog_id, msg_num, &inner);

    if locked.config.debug_wire {
        info!("[wire] RESPONSE HEX: {}", hex_dump(&response));
    }

    // Base64-encode response
    let encoded = BASE64.encode(&response);
    drop(locked);

    (StatusCode::OK, Bytes::from(encoded))
}

fn hex_dump(data: &[u8]) -> String {
    data.iter().take(128).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.debug_wire || cli.verbose {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter))
        )
        .with_target(false)
        .init();

    // Build fixtures
    let fixtures = Fixtures::default();

    // Build prefix for dialog/system IDs.
    // IMPORTANT: Must NOT contain FinTS separator chars (+, :, ', @, ?)
    // Use only alphanumeric characters.
    let dialog_prefix = {
        let bytes: Vec<u8> = (0..9).map(|_| rand::random::<u8>()).collect();
        bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    };
    let system_prefix = {
        let bytes: Vec<u8> = (0..9).map(|_| rand::random::<u8>()).collect();
        bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    };

    // Bind listener first to know the actual port
    let addr = format!("{}:{}", cli.host, cli.port);
    let listener = TcpListener::bind(&addr).await?;
    let actual_addr = listener.local_addr()?;
    let actual_port = actual_addr.port();

    let config = ServerConfig {
        tan_mode: cli.tan_mode,
        auto_confirm_secs: cli.auto_confirm_secs,
        error_on: cli.error_on,
        error_type: cli.error_type,
        fixtures,
        verbose: cli.verbose,
        debug_wire: cli.debug_wire,
        latency_ms: cli.latency_ms,
    };

    let state = Arc::new(Mutex::new(ServerState {
        config,
        dialogs: HashMap::new(),
        systems: HashMap::new(),
        dialog_counter: 0,
        system_counter: 0,
        dialog_prefix,
        system_prefix,
        port: actual_port,
    }));

    let app = Router::new()
        .route("/", post(handle_fints_request))
        .with_state(state);

    // Print ready signal
    if cli.print_ready || cli.port == 0 {
        println!("READY:{}", actual_port);
        std::io::Write::flush(&mut std::io::stdout())?;
    } else {
        info!("FinTS mock server listening on http://{}/", actual_addr);
        info!("TAN mode: {:?}", cli.tan_mode);
        if cli.tan_mode == TanMode::Decoupled {
            info!("Auto-confirm: {} seconds", cli.auto_confirm_secs);
        }
    }

    axum::serve(listener, app).await?;

    Ok(())
}
