//! Response segment parsers: extract typed data from bank response segments.

use chrono::NaiveDate;
use rust_decimal::Decimal;
use std::str::FromStr;

use crate::parser::RawSegment;
use crate::types::*;

/// Heuristic check if a string looks like an IBAN.
/// IBANs are 15-34 characters: 2-letter country code + 2-digit check + BBAN.
fn looks_like_iban(s: &str) -> bool {
    let len = s.len();
    if !(15..=34).contains(&len) {
        return false;
    }
    let bytes = s.as_bytes();
    // First 2 chars must be uppercase letters (country code)
    bytes[0].is_ascii_uppercase()
        && bytes[1].is_ascii_uppercase()
        // Next 2 chars must be digits (check digits)
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        // Rest must be alphanumeric
        && bytes[4..].iter().all(|b| b.is_ascii_alphanumeric())
}

/// Heuristic check if a string looks like a BIC/SWIFT code.
/// BICs are 8 or 11 characters: 4 alpha (bank) + 2 alpha (country) + 2 alnum (location) [+ 3 alnum (branch)].
fn looks_like_bic(s: &str) -> bool {
    let len = s.len();
    if len != 8 && len != 11 {
        return false;
    }
    let bytes = s.as_bytes();
    // First 6 chars must be alphabetic (bank code + country code)
    bytes[..6].iter().all(|b| b.is_ascii_alphabetic())
        // Remaining chars must be alphanumeric (location + optional branch)
        && bytes[6..].iter().all(|b| b.is_ascii_alphanumeric())
}

/// Parse TAN methods from HITANS response segment(s).
/// HITANS contains TwoStepParameters (one per supported TAN method) in its DEGs.
pub(crate) fn parse_hitans(seg: &RawSegment) -> Vec<TanMethod> {
    let version = seg.segment_version();
    let mut methods = Vec::new();

    // HITANS structure varies by version but the TAN parameters start at DEG 4+
    // DEG 1 = header, DEG 2 = max one-step jobs, DEG 3 = security class,
    // DEG 4+ = two-step parameters (one DEG per method)
    for i in 4..seg.deg_count() {
        let d = seg.deg(i);
        if d.len() < 3 {
            continue;
        }

        let security_function = d.get_str(0);
        if security_function.is_empty() {
            continue;
        }

        let tan_process = d.get_str(1);
        // Name is at different positions depending on version
        let name = if version >= 6 {
            d.get_str(3) // Index 3 for v6/v7
        } else {
            d.get_str(2) // Index 2 for older versions
        };

        let needs_tan_medium = if version >= 6 && d.len() > 13 {
            let val = d.get_str(13);
            val == "2" || val == "1" // 2 = required, 1 = allowed
        } else {
            false
        };

        // Decoupled parameters (v7 only, high indices)
        let (is_decoupled, max_polls, wait_first, wait_next) = if version >= 7 && d.len() > 24 {
            let decoupled = d.get_str(21) == "J";
            let max_p = d.get_str(22).parse::<i32>().unwrap_or(-1);
            let wf = d.get_str(23).parse::<i32>().unwrap_or(0);
            let wn = d.get_str(24).parse::<i32>().unwrap_or(0);
            (decoupled, max_p, wf, wn)
        } else {
            (false, -1, 0, 0)
        };

        let display_name = if name.is_empty() {
            format!("TAN-{}", &security_function)
        } else {
            name
        };

        methods.push(TanMethod {
            security_function: SecurityFunction::new(security_function),
            tan_process: TanProcess::from_str_val(&tan_process),
            name: display_name,
            needs_tan_medium,
            decoupled_max_polls: max_polls,
            wait_before_first_poll: wait_first,
            wait_before_next_poll: wait_next,
            is_decoupled,
            hktan_version: version,
        });
    }

    methods
}

/// Parse HITAN (TAN challenge response) — extracts challenge and task reference.
pub(crate) fn parse_hitan(seg: &RawSegment) -> (String, String, Option<Vec<u8>>) {
    let version = seg.segment_version();

    // HITAN structure:
    // v6/v7: DEG1=header, DEG2=tan_process, DEG3=order_hash, DEG4=task_ref, DEG5=challenge, DEG6=challenge_hhduc, DEG7=validity
    // v3-5: slightly different layout
    let (task_ref, challenge, challenge_hhduc) = if version >= 6 {
        let task_ref = read_str(seg, 2, 0); // DEG 2 = task reference (or order_reference)
                                            // In some bank implementations, the structure varies.
                                            // We search for the task reference and challenge text in a pragmatic way.
        let task_reference = if task_ref.is_empty() {
            read_str(seg, 3, 0)
        } else {
            task_ref
        };
        let challenge = read_str(seg, 4, 0);
        let challenge_text = if challenge.is_empty() {
            read_str(seg, 3, 0)
        } else {
            challenge
        };
        let hhduc = read_binary(seg, 5, 0);
        (task_reference, challenge_text, hhduc)
    } else {
        let task_ref = read_str(seg, 2, 0);
        let challenge = read_str(seg, 3, 0);
        (task_ref, challenge, None)
    };

    (task_ref, challenge, challenge_hhduc)
}

/// Parse HITAB (TAN media list response).
/// Returns a list of TAN medium names (e.g. "Handy-Nr. +49 151 xxx", "Authenticator App").
/// These are the registered devices/channels that can receive pushTAN notifications.
pub(crate) fn parse_hitab(seg: &RawSegment) -> Vec<String> {
    let mut media = Vec::new();

    // HITAB: DEG0=header, DEG1+=TanMediumList entries
    // Each entry is a DEG with: status:medium_class:medium_name[:mobile_no_masked:...]
    // status: A=active, I=inactive, B=blocked
    for i in 1..seg.deg_count() {
        let d = seg.deg(i);
        if d.len() < 3 {
            continue;
        }
        let status = d.get_str(0);
        // Only include active media
        if status != "A" && status != "1" {
            continue;
        }
        let name = d.get_str(2);
        if !name.is_empty() {
            media.push(name);
        }
    }

    media
}

/// Parse HISPA (SEPA account information response).
pub(crate) fn parse_hispa(seg: &RawSegment) -> Vec<SepaAccount> {
    let mut accounts = Vec::new();

    // HISPA: DEG1=header, DEG2+=account connection data (KTZ1)
    // Each KTZ1 DEG: is_sepa_account:iban:bic:account_number:sub_account:country:blz
    for i in 1..seg.deg_count() {
        let d = seg.deg(i);
        if d.len() < 2 {
            continue;
        }

        // The structure can be: J:IBAN:BIC:AccNo:Sub:280:BLZ or IBAN:BIC:AccNo:Sub:280:BLZ
        let (iban, bic, acc_no, sub_acc, blz) = if d.get_str(0) == "J" || d.get_str(0) == "N" {
            // Has is_sepa prefix
            (
                d.get_str(1),
                d.get_str(2),
                d.get_str(3),
                d.get_str(4),
                d.get_str(6),
            )
        } else {
            (
                d.get_str(0),
                d.get_str(1),
                d.get_str(2),
                d.get_str(3),
                d.get_str(5),
            )
        };

        if iban.is_empty() {
            continue;
        }

        accounts.push(SepaAccount {
            iban: Iban::new(iban),
            bic: Bic::new(bic),
            account_number: acc_no,
            sub_account: sub_acc,
            blz: Blz::new(blz),
            owner: None,
            product_name: None,
            currency: None,
        });
    }

    accounts
}

/// Parse HIUPD (User Parameter Data) for account info including owner/product name.
pub(crate) fn parse_hiupd(seg: &RawSegment) -> Option<SepaAccount> {
    // HIUPD: DEG1=header, DEG2=account(KTO), DEG3=customer_id, DEG4=upd_usage, DEG5=account_type?,
    //        DEG6=currency?, DEG7=owner_name1, DEG8=owner_name2?, DEG9=product_name?
    if seg.deg_count() < 3 {
        return None;
    }

    let acct_deg = seg.deg(1);
    let account_number = acct_deg.get_str(0);
    let sub_account = acct_deg.get_str(1);
    let blz = acct_deg.get_str(3);

    // IBAN and BIC might be at the end of the segment or in specific positions.
    // Some banks put IBAN at DEG index ~10+, so we scan all DEGs heuristically.
    let mut iban = String::new();
    let mut bic = String::new();

    for i in 1..seg.deg_count() {
        let s = seg.deg(i).get_str(0);
        if iban.is_empty() && looks_like_iban(&s) {
            iban = s.clone();
        } else if bic.is_empty() && i > 1 && looks_like_bic(&s) {
            bic = s;
        }
    }

    let owner = read_opt_str(seg, 6, 0).or_else(|| read_opt_str(seg, 7, 0));
    let product_name = read_opt_str(seg, 8, 0).or_else(|| read_opt_str(seg, 9, 0));
    let currency = read_opt_str(seg, 5, 0);

    Some(SepaAccount {
        iban: Iban::new(iban),
        bic: Bic::new(bic),
        account_number,
        sub_account,
        blz: Blz::new(blz),
        owner,
        product_name,
        currency: currency.map(Currency::new),
    })
}

/// Parse HISAL (balance response).
pub(crate) fn parse_hisal(seg: &RawSegment) -> Option<AccountBalance> {
    // HISAL structure (all versions v5-v7):
    //   DEG0=header, DEG1=account(KTO/KTI), DEG2=product_name, DEG3=currency,
    //   DEG4=booked_balance, DEG5=pending_balance?, DEG6=credit_line?, DEG7=available?
    // The booked balance DEG format: debit_credit:amount:currency:date
    let balance_deg_idx = 4;
    let bal_deg = seg.deg(balance_deg_idx);

    if bal_deg.len() < 3 {
        return None;
    }

    let dc_indicator = bal_deg.get_str(0);
    let amount_str = bal_deg.get_str(1).replace(',', ".");
    let currency = bal_deg.get_str(2);
    let date_str = bal_deg.get_str(3);

    let amount = Decimal::from_str(&amount_str).ok()?;
    let final_amount = if dc_indicator == "D" { -amount } else { amount };

    let date = if date_str.len() == 8 {
        NaiveDate::parse_from_str(&date_str, "%Y%m%d").ok()
    } else {
        None
    };

    let currency_from_header = read_str(seg, 3, 0);
    let final_currency = if currency.is_empty() {
        currency_from_header
    } else {
        currency
    };

    // Pending balance (DEG 5) — same format as booked balance
    let (pending_amount, pending_date) = {
        let pend_deg = seg.deg(balance_deg_idx + 1);
        if pend_deg.len() >= 2 {
            let pdc = pend_deg.get_str(0);
            let pamt_str = pend_deg.get_str(1).replace(',', ".");
            let pdate_str = pend_deg.get_str(3);
            let pamt = Decimal::from_str(&pamt_str)
                .ok()
                .map(|a| if pdc == "D" { -a } else { a });
            let pdate = if pdate_str.len() == 8 {
                NaiveDate::parse_from_str(&pdate_str, "%Y%m%d").ok()
            } else {
                None
            };
            (pamt, pdate)
        } else {
            (None, None)
        }
    };

    // Credit line (DEG 6)
    let credit_line = {
        let cl_deg = seg.deg(balance_deg_idx + 2);
        if cl_deg.len() >= 1 {
            let cl_str = cl_deg.get_str(0).replace(',', ".");
            Decimal::from_str(&cl_str).ok()
        } else {
            None
        }
    };

    // Available amount (DEG 7)
    let available = {
        let av_deg = seg.deg(balance_deg_idx + 3);
        if av_deg.len() >= 1 {
            let av_str = av_deg.get_str(0).replace(',', ".");
            Decimal::from_str(&av_str).ok()
        } else {
            None
        }
    };

    Some(AccountBalance {
        amount: final_amount,
        date: date.unwrap_or_else(|| chrono::Utc::now().date_naive()),
        currency: Currency::new(if final_currency.is_empty() {
            "EUR"
        } else {
            &final_currency
        }),
        credit_line,
        available,
        pending_amount,
        pending_date,
    })
}

/// Extracted MT940 data from HIKAZ segments, separated into booked and pending.
pub struct Mt940ExtractedData {
    pub booked: Vec<u8>,
    pub pending: Vec<u8>,
}

/// Parse HIKAZ (statement response) — extracts the raw MT940 binary data.
/// Returns booked and pending transaction data separately from all HIKAZ segments.
pub(crate) fn extract_mt940_data(segments: &[RawSegment]) -> Mt940ExtractedData {
    let mut booked = Vec::new();
    let mut pending = Vec::new();

    for seg in segments {
        if seg.segment_type() == "HIKAZ" {
            // DEG 1 = booked transactions (binary MT940)
            if let Some(data) = read_binary(seg, 1, 0) {
                booked.extend_from_slice(&data);
            }
            // DEG 2 = pending transactions (optional, also MT940 binary)
            if let Some(data) = read_binary(seg, 2, 0) {
                pending.extend_from_slice(&data);
            }
        }
    }

    Mt940ExtractedData { booked, pending }
}

/// Parse HIWPD (securities depot response) — extracts holdings.
///
/// HIWPD response segment structure per FinTS spec:
///   DEG0 = header (HIWPD:seg_num:version:ref)
///   DEG1 = depot account (KTI or KTO)
///   DEG2+ = securities positions
///
/// Each position DEG contains:
///   - ISIN (International Securities Identification Number)
///   - WKN (Wertpapierkennnummer)
///   - Security name
///   - Quantity (number of shares/units)
///   - Price info (amount, currency, date)
///   - Market value (total value of position)
///   - Exchange info
///
/// The exact DEG layout varies by version and bank. We use a heuristic parser
/// that handles the common structures from major German banks.
pub(crate) fn parse_hiwpd(segments: &[RawSegment]) -> Vec<SecurityHolding> {
    let mut holdings = Vec::new();

    for seg in segments {
        if seg.segment_type() != "HIWPD" {
            continue;
        }

        // Skip header (DEG0) and account (DEG1), positions start at DEG2+
        for i in 2..seg.deg_count() {
            let d = seg.deg(i);
            if d.len() < 3 {
                continue;
            }

            // Position DEG layout (common pattern for v1-v7):
            // The structure varies, but typically:
            //   [0] = piece marker or ISIN
            //   [1] = ISIN or WKN
            //   [2] = WKN or name
            //   [3] = name or quantity
            //   [4..] = quantity, price, currency, date, market_value, etc.
            //
            // We use heuristic detection: ISIN is 12 chars starting with 2 letters,
            // WKN is 6 alphanumeric chars.
            let holding = parse_holding_deg(d);
            if let Some(h) = holding {
                holdings.push(h);
            }
        }
    }

    holdings
}

/// Every binary payload a `HIWPD` answer carries, in the order the bank
/// stated it.
///
/// A bank may state its positions in one binary DEG rather than one position
/// per DEG, a shape the heuristic above cannot read. A caller that parses the
/// payload itself takes the bytes from here rather than losing the answer to
/// `Empty`.
pub(crate) fn hiwpd_payloads(segments: &[RawSegment]) -> Vec<Vec<u8>> {
    let mut payloads = Vec::new();

    for seg in segments {
        if seg.segment_type() != "HIWPD" {
            continue;
        }
        for i in 0..seg.deg_count() {
            let d = seg.deg(i);
            for j in 0..d.len() {
                if let Some(bytes) = d.get(j).as_bytes() {
                    payloads.push(bytes.to_vec());
                }
            }
        }
    }

    payloads
}

/// Parse a single holding position from a DEG.
/// Uses heuristic detection since HIWPD layout varies between banks and versions.
fn parse_holding_deg(d: &crate::parser::DEG) -> Option<SecurityHolding> {
    if d.len() < 3 {
        return None;
    }

    let mut isin: Option<String> = None;
    let mut wkn: Option<String> = None;
    let mut name = String::new();
    let mut quantity: Option<Decimal> = None;
    let mut price: Option<Decimal> = None;
    let mut price_currency: Option<String> = None;
    let mut price_date: Option<NaiveDate> = None;
    let mut market_value: Option<Decimal> = None;
    let mut market_value_currency: Option<String> = None;
    let mut exchange: Option<String> = None;

    // Scan all DEs looking for recognizable fields
    for idx in 0..d.len() {
        let val = d.get_str(idx);
        if val.is_empty() {
            continue;
        }

        // ISIN: exactly 12 chars, starts with 2 uppercase letters
        if isin.is_none() && looks_like_isin(&val) {
            isin = Some(val);
            continue;
        }

        // WKN: exactly 6 alphanumeric chars (and not already identified as something else)
        if wkn.is_none() && looks_like_wkn(&val) && isin.is_some() {
            wkn = Some(val);
            continue;
        }

        // Date: 8 digits in YYYYMMDD format
        if price_date.is_none() && val.len() == 8 && val.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(date) = NaiveDate::parse_from_str(&val, "%Y%m%d") {
                price_date = Some(date);
                continue;
            }
        }

        // Currency: exactly 3 uppercase letters (ISO 4217)
        if val.len() == 3 && val.chars().all(|c| c.is_ascii_uppercase()) {
            if price_currency.is_none() && (price.is_some() || quantity.is_some()) {
                price_currency = Some(val.clone());
                if market_value_currency.is_none() {
                    market_value_currency = Some(val);
                }
                continue;
            } else if market_value_currency.is_none() {
                market_value_currency = Some(val);
                continue;
            }
        }

        // Decimal amount: contains comma (FinTS uses comma as decimal separator)
        if val.contains(',')
            || (val
                .chars()
                .all(|c| c.is_ascii_digit() || c == ',' || c == '.')
                && !val.is_empty())
        {
            let normalized = val.replace(',', ".");
            if let Ok(dec) = Decimal::from_str(&normalized) {
                if quantity.is_none() {
                    quantity = Some(dec);
                } else if price.is_none() {
                    price = Some(dec);
                } else if market_value.is_none() {
                    market_value = Some(dec);
                }
                continue;
            }
        }

        // Name: longer string that's not a number, not an ISIN, not a WKN
        if name.is_empty()
            && val.len() > 2
            && isin.is_some()
            && !val.chars().next().unwrap_or(' ').is_ascii_digit()
        {
            name = val;
            continue;
        }

        // Exchange: typically a short name like "XETRA", "FRA", etc.
        if exchange.is_none()
            && val.len() >= 2
            && val.len() <= 10
            && val.chars().all(|c| c.is_ascii_alphabetic())
            && isin.is_some()
            && !name.is_empty()
        {
            exchange = Some(val);
        }
    }

    // At minimum we need an ISIN or WKN and a quantity
    if isin.is_none() && wkn.is_none() {
        return None;
    }
    let quantity = quantity.unwrap_or_else(|| Decimal::ZERO);

    // Compute market value from quantity * price if not explicitly given
    if market_value.is_none() {
        if let Some(p) = price {
            market_value = Some(quantity * p);
        }
    }

    let raw = serde_json::json!({
        "isin": isin,
        "wkn": wkn,
        "name": name,
        "quantity": quantity.to_string(),
        "price": price.map(|p| p.to_string()),
        "price_currency": price_currency,
        "price_date": price_date.map(|d| d.to_string()),
        "market_value": market_value.map(|v| v.to_string()),
        "exchange": exchange,
    });

    Some(SecurityHolding {
        isin: isin.map(Isin::new),
        wkn: wkn.map(Wkn::new),
        name,
        quantity,
        price,
        price_currency: price_currency.map(Currency::new),
        price_date,
        market_value,
        market_value_currency: market_value_currency.map(Currency::new),
        acquisition_value: None,
        profit_loss: None,
        exchange,
        depot_id: None,
        raw,
    })
}

/// Check if a string looks like an ISIN.
/// ISIN: exactly 12 characters, first 2 are uppercase letters, last is a check digit.
fn looks_like_isin(s: &str) -> bool {
    s.len() == 12
        && s.as_bytes()[0].is_ascii_uppercase()
        && s.as_bytes()[1].is_ascii_uppercase()
        && s.as_bytes()[2..].iter().all(|b| b.is_ascii_alphanumeric())
}

/// Check if a string looks like a WKN.
/// WKN: exactly 6 alphanumeric characters.
fn looks_like_wkn(s: &str) -> bool {
    s.len() == 6 && s.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Parse HIBPA (Bank Parameter Data header) — extracts BPD version.
pub(crate) fn parse_hibpa_version(seg: &RawSegment) -> u16 {
    read_u16(seg, 1, 0)
}

/// Parse HIUPA (User Parameter Data header) — extracts UPD version.
pub(crate) fn parse_hiupa_version(seg: &RawSegment) -> u16 {
    read_u16(seg, 3, 0)
}

/// Parse HISYN (Synchronization response) — extracts the assigned system ID.
pub(crate) fn parse_hisyn_system_id(seg: &RawSegment) -> String {
    read_str(seg, 1, 0)
}

/// Extract allowed TAN security functions from response code 3920.
pub(crate) fn extract_allowed_security_functions(codes: &[ResponseCode]) -> Vec<SecurityFunction> {
    for code in codes {
        if let ResponseCodeKind::AllowedSecurityFunctions(ref sfs) = code.kind {
            return sfs.clone();
        }
    }
    Vec::new()
}

/// Parse HIPINS: which operations require PIN authentication.
pub(crate) fn parse_hipins(seg: &RawSegment) -> std::collections::HashMap<SegmentType, bool> {
    let mut map = std::collections::HashMap::new();

    for deg_idx in 1..seg.deg_count() {
        let d = seg.deg(deg_idx);
        let mut i = 0;
        while i + 1 < d.len() {
            let key = d.get_str(i);
            let val = d.get_str(i + 1);
            if key.len() == 5 && key.starts_with("HK") && (val == "J" || val == "N") {
                map.insert(SegmentType::new(key), val == "J");
                i += 2;
            } else {
                i += 1;
            }
        }
    }

    map
}

/// Extract touchdown point from response codes.
pub(crate) fn find_touchdown(codes: &[ResponseCode]) -> Option<TouchdownPoint> {
    for code in codes {
        if let ResponseCodeKind::Touchdown(ref td) = code.kind {
            return Some(td.clone());
        }
    }
    None
}

/// Check response codes for errors and return the first error found.
pub(crate) fn find_error(codes: &[ResponseCode]) -> Option<&ResponseCode> {
    codes.iter().find(|c| c.is_error())
}

/// Find the highest supported version for a segment type from BPD parameter segments.
/// BPD parameter segments follow the naming pattern: HI____S (6 chars, ending in S).
/// For example, HKSPA -> HISPAS, HKSAL -> HISALS, HKKAZ -> HIKAZS.
pub(crate) fn find_highest_segment_version(
    segments: &[RawSegment],
    parameter_segment_type: &str,
    max_client_version: u16,
) -> u16 {
    let mut highest = 0;

    for seg in segments {
        if seg.segment_type() == parameter_segment_type {
            let v = seg.segment_version();
            if v <= max_client_version && v > highest {
                highest = v;
            }
        }
    }

    highest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    /// Helper: parse a raw FinTS segment string into a RawSegment.
    fn parse_segment(s: &str) -> RawSegment {
        let segments = parser::parse_message(s.as_bytes()).unwrap();
        segments.into_iter().next().unwrap()
    }

    // ── IBAN / BIC heuristics ──────────────────────────────────────────

    #[test]
    fn test_looks_like_iban_valid() {
        assert!(looks_like_iban("DE89370400440532013000"));
        assert!(looks_like_iban("GB29NWBK60161331926819"));
        assert!(looks_like_iban("FR7630006000011234567890189"));
    }

    #[test]
    fn test_looks_like_iban_invalid() {
        assert!(!looks_like_iban(""));
        assert!(!looks_like_iban("DE89")); // too short
        assert!(!looks_like_iban("1234567890123456")); // no country code
        assert!(!looks_like_iban("de89370400440532013000")); // lowercase country
    }

    #[test]
    fn test_looks_like_bic_valid() {
        assert!(looks_like_bic("COBADEFF")); // 8 chars
        assert!(looks_like_bic("COBADEFFXXX")); // 11 chars
        assert!(looks_like_bic("BYLADEM1001")); // 11 chars with digits in location/branch
    }

    #[test]
    fn test_looks_like_bic_invalid() {
        assert!(!looks_like_bic(""));
        assert!(!looks_like_bic("COBADE")); // too short (6)
        assert!(!looks_like_bic("COBADEFF1")); // wrong length (9)
        assert!(!looks_like_bic("12BADEFFXXX")); // digits in bank code
    }

    // ── Simple parsers ─────────────────────────────────────────────────

    #[test]
    fn test_parse_hibpa_version() {
        let seg = parse_segment("HIBPA:5:3:4+42+280+0+1+1+0'");
        assert_eq!(parse_hibpa_version(&seg), 42);
    }

    #[test]
    fn test_parse_hiupa_version() {
        let seg = parse_segment("HIUPA:6:4:4+test1+7+0'");
        assert_eq!(parse_hiupa_version(&seg), 0); // version is at DEG 3 index 0
    }

    #[test]
    fn test_parse_hisyn_system_id() {
        let seg = parse_segment("HISYN:173:4:6+MYSYSID123'");
        assert_eq!(parse_hisyn_system_id(&seg), "MYSYSID123");
    }

    // ── Response code helpers ──────────────────────────────────────────

    #[test]
    fn test_extract_allowed_security_functions_empty() {
        let codes = vec![ResponseCode::new("0020", "OK")];
        assert!(extract_allowed_security_functions(&codes).is_empty());
    }

    #[test]
    fn test_extract_allowed_security_functions() {
        let codes = vec![ResponseCode::with_params(
            "3920",
            "Zugelassene Verfahren",
            vec!["912".into(), "940".into()],
        )];
        let sfs = extract_allowed_security_functions(&codes);
        assert_eq!(sfs.len(), 2);
        assert_eq!(sfs[0], SecurityFunction::new("912"));
        assert_eq!(sfs[1], SecurityFunction::new("940"));
    }

    #[test]
    fn test_find_touchdown() {
        let codes = vec![
            ResponseCode::new("0020", "OK"),
            ResponseCode::with_params("3040", "Aufsetzpunkt", vec!["TOUCH123".into()]),
        ];
        let td = find_touchdown(&codes);
        assert_eq!(td, Some(TouchdownPoint::new("TOUCH123")));
    }

    #[test]
    fn test_find_touchdown_none() {
        let codes = vec![ResponseCode::new("0020", "OK")];
        assert!(find_touchdown(&codes).is_none());
    }

    #[test]
    fn test_find_error_present() {
        let codes = vec![
            ResponseCode::new("0020", "OK"),
            ResponseCode::new("9010", "General error"),
        ];
        let err = find_error(&codes);
        assert!(err.is_some());
        assert!(err.unwrap().is_error());
    }

    #[test]
    fn test_find_error_absent() {
        let codes = vec![ResponseCode::new("0020", "OK")];
        assert!(find_error(&codes).is_none());
    }

    // ── HIPINS parser ──────────────────────────────────────────────────

    #[test]
    fn test_parse_hipins() {
        // Simplified HIPINS segment with operation TAN requirements
        let seg = parse_segment("HIPINS:6:1:4+1+1+0+HKSAL:N+HKKAZ:N+HKCCS:J+HKTAN:N'");
        let map = parse_hipins(&seg);
        assert_eq!(map.get(&SegmentType::new("HKSAL")), Some(&false));
        assert_eq!(map.get(&SegmentType::new("HKKAZ")), Some(&false));
        assert_eq!(map.get(&SegmentType::new("HKCCS")), Some(&true));
        assert_eq!(map.get(&SegmentType::new("HKTAN")), Some(&false));
    }

    // ── Segment version lookup ─────────────────────────────────────────

    #[test]
    fn test_find_highest_segment_version() {
        let seg_v5 = parse_segment("HISALS:10:5:4+1+1'");
        let seg_v7 = parse_segment("HISALS:11:7:4+1+1'");
        let segments = vec![seg_v5, seg_v7];

        // Max 7 → should find v7
        assert_eq!(find_highest_segment_version(&segments, "HISALS", 7), 7);
        // Max 6 → should find v5 (v7 exceeds max)
        assert_eq!(find_highest_segment_version(&segments, "HISALS", 6), 5);
        // Unknown segment → 0
        assert_eq!(find_highest_segment_version(&segments, "HIXXXS", 7), 0);
    }

    // ── ISIN / WKN heuristics ──────────────────────────────────────────

    #[test]
    fn test_looks_like_isin_valid() {
        assert!(looks_like_isin("DE0005140008")); // Deutsche Bank
        assert!(looks_like_isin("US0378331005")); // Apple
        assert!(looks_like_isin("IE00B4L5Y983")); // iShares MSCI World
        assert!(looks_like_isin("LU0274208692")); // Xtrackers
    }

    #[test]
    fn test_looks_like_isin_invalid() {
        assert!(!looks_like_isin(""));
        assert!(!looks_like_isin("DE000514000")); // too short (11)
        assert!(!looks_like_isin("DE00051400089")); // too long (13)
        assert!(!looks_like_isin("1E0005140008")); // starts with digit
        assert!(!looks_like_isin("de0005140008")); // lowercase
    }

    #[test]
    fn test_looks_like_wkn_valid() {
        assert!(looks_like_wkn("514000")); // Deutsche Bank
        assert!(looks_like_wkn("A1JMDF")); // iShares MSCI World
        assert!(looks_like_wkn("DBX1MW")); // Xtrackers
    }

    #[test]
    fn test_looks_like_wkn_invalid() {
        assert!(!looks_like_wkn(""));
        assert!(!looks_like_wkn("51400")); // too short (5)
        assert!(!looks_like_wkn("5140001")); // too long (7)
        assert!(!looks_like_wkn("514-00")); // contains hyphen
    }

    // ── HIWPD parser ───────────────────────────────────────────────────

    #[test]
    fn test_parse_hiwpd_basic() {
        // Simulate a HIWPD segment with one holding position
        // DEG0=header, DEG1=account, DEG2=position
        // Position: ISIN:WKN:name:quantity:price:currency:date
        let seg = parse_segment(
            "HIWPD:5:6:3+DE04120300001084174299:BYLADEM1001+DE0005140008:514000:DEUTSCHE BANK AG:100,00:42,50:EUR:20260315'"
        );
        let holdings = parse_hiwpd(&[seg]);
        assert_eq!(holdings.len(), 1);

        let h = &holdings[0];
        assert_eq!(h.isin.as_ref().unwrap().as_str(), "DE0005140008");
        assert_eq!(h.wkn.as_ref().unwrap().as_str(), "514000");
        assert_eq!(h.name, "DEUTSCHE BANK AG");
        assert_eq!(h.quantity, rust_decimal::Decimal::new(10000, 2)); // 100.00
        assert_eq!(h.price, Some(rust_decimal::Decimal::new(4250, 2))); // 42.50
        assert_eq!(h.price_currency.as_ref().unwrap().as_str(), "EUR");
        assert_eq!(
            h.price_date,
            Some(chrono::NaiveDate::from_ymd_opt(2026, 3, 15).unwrap())
        );
    }

    #[test]
    fn test_parse_hiwpd_multiple_positions() {
        // Two positions in one HIWPD segment
        let seg = parse_segment(
            "HIWPD:5:6:3+DE04120300001084174299:BYLADEM1001+DE0005140008:514000:DEUTSCHE BANK:100,00:42,50:EUR:20260315+US0378331005:865985:APPLE INC:25,00:178,30:USD:20260314'"
        );
        let holdings = parse_hiwpd(&[seg]);
        assert_eq!(holdings.len(), 2);

        assert_eq!(holdings[0].isin.as_ref().unwrap().as_str(), "DE0005140008");
        assert_eq!(holdings[0].name, "DEUTSCHE BANK");

        assert_eq!(holdings[1].isin.as_ref().unwrap().as_str(), "US0378331005");
        assert_eq!(holdings[1].wkn.as_ref().unwrap().as_str(), "865985");
        assert_eq!(holdings[1].name, "APPLE INC");
        assert_eq!(holdings[1].quantity, rust_decimal::Decimal::new(2500, 2));
    }

    #[test]
    fn test_parse_hiwpd_empty() {
        // HIWPD with only header + account, no positions
        let seg = parse_segment("HIWPD:5:6:3+DE04120300001084174299:BYLADEM1001'");
        let holdings = parse_hiwpd(&[seg]);
        assert!(holdings.is_empty());
    }

    #[test]
    fn test_hiwpd_payloads_collect_the_binary_deg() {
        let seg = parse_segment("HIWPD:4:6:3+@5@hello'");
        assert_eq!(hiwpd_payloads(&[seg]), vec![b"hello".to_vec()]);
    }

    #[test]
    fn test_hiwpd_payloads_ignore_structured_positions() {
        let seg = parse_segment(
            "HIWPD:5:6:3+DE04120300001084174299:BYLADEM1001+DE0005140008:514000:DEUTSCHE BANK AG:100,00:42,50:EUR:20260315'"
        );
        assert!(hiwpd_payloads(&[seg]).is_empty());
    }

    #[test]
    fn test_parse_hiwpd_multiple_segments() {
        // Holdings spread across two HIWPD segments (pagination)
        let seg1 = parse_segment(
            "HIWPD:5:6:3+DE04120300001084174299:BYLADEM1001+DE0005140008:514000:DEUTSCHE BANK:100,00:42,50:EUR:20260315'"
        );
        let seg2 = parse_segment(
            "HIWPD:6:6:3+DE04120300001084174299:BYLADEM1001+US0378331005:865985:APPLE INC:25,00:178,30:USD:20260314'"
        );
        let holdings = parse_hiwpd(&[seg1, seg2]);
        assert_eq!(holdings.len(), 2);
    }

    #[test]
    fn test_parse_hiwpd_ignores_non_hiwpd() {
        // Non-HIWPD segments should be ignored
        let seg =
            parse_segment("HISAL:5:7:3+DE04120300001084174299:BYLADEM1001+C:1234,56:EUR:20260315'");
        let holdings = parse_hiwpd(&[seg]);
        assert!(holdings.is_empty());
    }

    #[test]
    fn test_parse_hiwpd_market_value_computed() {
        // When market value is not explicit, it should be computed from quantity * price
        let seg = parse_segment(
            "HIWPD:5:6:3+DE04120300001084174299:BYLADEM1001+DE0005140008:514000:DEUTSCHE BANK:10,00:100,00:EUR:20260315'"
        );
        let holdings = parse_hiwpd(&[seg]);
        assert_eq!(holdings.len(), 1);
        let h = &holdings[0];
        // 10.00 * 100.00 = 1000.00
        assert_eq!(h.market_value, Some(rust_decimal::Decimal::new(100000, 2)));
    }

    #[test]
    fn test_parse_hiwpd_isin_only() {
        // Position with ISIN but no WKN (only 2-char WKN-like string won't match)
        let seg = parse_segment(
            "HIWPD:5:6:3+DE04120300001084174299:BYLADEM1001+IE00B4L5Y983:ISHARES MSCI WORLD:50,00:85,20:EUR:20260315'"
        );
        let holdings = parse_hiwpd(&[seg]);
        assert_eq!(holdings.len(), 1);
        assert_eq!(holdings[0].isin.as_ref().unwrap().as_str(), "IE00B4L5Y983");
        // WKN is None because "ISHARES MSCI WORLD" is not 6 alnum chars
        assert!(holdings[0].wkn.is_none());
    }

    #[test]
    fn test_find_highest_segment_version_hiwpds() {
        let seg_v1 = parse_segment("HIWPDS:10:1:4+1+1'");
        let seg_v6 = parse_segment("HIWPDS:11:6:4+1+1'");
        let segments = vec![seg_v1, seg_v6];

        assert_eq!(find_highest_segment_version(&segments, "HIWPDS", 7), 6);
        assert_eq!(find_highest_segment_version(&segments, "HIWPDS", 5), 1);
    }
}
