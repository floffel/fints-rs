//! Segment builders: functions that create `Vec<DEG>` for each request segment type.
//!
//! All builders are `pub(crate)` — they are internal implementation details.
//! External consumers should use the typed methods on `Dialog<Open>` instead.

use chrono::{Local, NaiveDate};

use crate::parser::{DEG, DataElement};
use crate::types::*;

// ---- KTI (Kontoverbindung International) ----

/// Typed representation of a KTI DEG (Kontoverbindung International, version 1).
///
/// Per the FinTS spec, KTI has 5 data elements in this order:
///   1. IBAN
///   2. BIC
///   3. Konto-/Depotnummer (account number, optional)
///   4. Unterkontomerkmal (sub-account feature, optional)
///   5. Kreditinstitutskennung (bank identifier DEG: country_code:blz, optional)
///
/// All fields except IBAN and BIC are optional. When using SEPA accounts,
/// only IBAN and BIC are populated — the serializer strips trailing empties,
/// so the wire format is simply `IBAN:BIC`.
///
/// Using a struct instead of a raw `Vec<DataElement>` ensures the field order
/// and presence are correct at compile time.
struct Kti {
    iban: String,
    bic: String,
}

impl Kti {
    /// Create a new KTI for the given IBAN and BIC.
    ///
    /// # Panics
    /// Panics if `iban` or `bic` is empty — these are programming errors, not runtime conditions.
    fn new(iban: &str, bic: &str) -> Self {
        assert!(!iban.is_empty(), "IBAN must not be empty in KTI DEG");
        assert!(
            !bic.is_empty(),
            "BIC must not be empty in KTI DEG — use the bank's BIC as fallback"
        );
        Self {
            iban: iban.to_string(),
            bic: bic.to_string(),
        }
    }

    /// Serialize into a DEG: `IBAN:BIC`.
    ///
    /// Only IBAN and BIC are populated. The remaining optional fields
    /// (account_number, sub-account, bank_identifier) are omitted — the
    /// serializer strips trailing empties automatically.
    fn to_deg(&self) -> DEG {
        deg(vec![
            DataElement::Text(self.iban.clone()),
            DataElement::Text(self.bic.clone()),
        ])
    }
}

fn pin_version(security_function: &str) -> &str {
    if security_function.parse::<u16>().unwrap() >= 998 {
        "1"
    } else {
        "2"
    }
}

/// Extract (account_number, blz) from a German IBAN.
/// DE IBANs: DE + 2 check + 8 BLZ + 10 account = 22 chars.
fn extract_de_iban_parts(iban: &str) -> (String, String) {
    if iban.len() == 22 && iban.starts_with("DE") {
        (iban[12..].to_string(), iban[4..12].to_string())
    } else {
        (iban.to_string(), String::new())
    }
}

// ---- Segment Header ----

/// Create a segment header DEG: `TYPE:NUMBER:VERSION`
pub(crate) fn seg_header(seg_type: &str, number: u16, version: u16) -> DEG {
    deg(vec![de_text(seg_type), de_num(number), de_num(version)])
}

/// Create a segment header with reference: `TYPE:NUMBER:VERSION:REFERENCE`
pub(crate) fn seg_header_ref(seg_type: &str, number: u16, version: u16, reference: u16) -> DEG {
    deg(vec![
        de_text(seg_type),
        de_num(number),
        de_num(version),
        de_num(reference),
    ])
}

// ---- HNHBK (Nachrichtenkopf) - Message Header, version 3 ----

/// Build HNHBK:1:3 (message header).
/// `message_size` should be 12-digit zero-padded. Caller must update this after final serialization.
pub(crate) fn hnhbk(message_size: u32, dialog_id: &str, message_number: u16) -> Vec<DEG> {
    vec![
        seg_header("HNHBK", 1, 3),
        deg1(de_text(&format!("{:012}", message_size))), // message size (12 digits)
        deg1(de_text("300")),                            // HBCI version 3.0
        deg1(de_text(dialog_id)),                        // dialog ID
        deg1(de_num(message_number)),                    // message number
    ]
}

// ---- HNHBS (Nachrichtenabschluss) - Message Trailer, version 1 ----

pub(crate) fn hnhbs(segment_number: u16, message_number: u16) -> Vec<DEG> {
    vec![
        seg_header("HNHBS", segment_number, 1),
        deg1(de_num(message_number)),
    ]
}

// ---- HNVSK (Verschlüsselungskopf) - Encryption Header, version 3 ----

/// Build HNVSK:998:3 with PinTan dummy encryption parameters.
pub(crate) fn hnvsk(
    blz: &str,
    user_id: &str,
    system_id: &str,
    security_function: &str,
) -> Vec<DEG> {
    vec![
        seg_header("HNVSK", 998, 3),
        deg(vec![de_text("PIN"), de_text(pin_version(security_function))]),
        deg1(de_text(security_function)),
        // Security role: 1 = ISS (issuer)
        deg1(de_text("1")),
        // Security identification: role=2(MS), cid=empty, identifier=system_id
        deg(vec![de_text("2"), de_empty(), de_text(system_id)]),
        // Security timestamp: type=1 (STS), date (YYYYMMDD), time (HHMMSS)
        {
            let now = Local::now();
            deg(vec![
                de_text("1"),
                de_text(&now.format("%Y%m%d").to_string()),
                de_text(&now.format("%H%M%S").to_string()),
            ])
        },
        // Encryption algorithm: dummy 2-key 3DES CBC
        // usage=2, op_mode=2, alg=13, key=@8@00000000, param_name=5, param_iv_name=1
        deg(vec![
            de_text("2"),
            de_text("2"),
            de_text("13"),
            de_binary(vec![0u8; 8]),
            de_text("5"),
            de_text("1"),
        ]),
        // Key name: country:blz:user_id:V(cipher):0:0
        deg(vec![
            de_text("280"),
            de_text(blz),
            de_text(user_id),
            de_text("V"),
            de_text("0"),
            de_text("0"),
        ]),
        // Compression: 0 = NULL
        deg1(de_text("0")),
    ]
}

// ---- HNVSD (Verschlüsselte Daten) - Encrypted Data Container, version 1 ----

/// Build HNVSD:999:1 wrapping inner segment bytes.
pub(crate) fn hnvsd(inner_bytes: &[u8]) -> Vec<DEG> {
    vec![
        seg_header("HNVSD", 999, 1),
        deg1(de_binary(inner_bytes.to_vec())),
    ]
}

// ---- HNSHK (Signaturkopf) - Signature Header, version 4 ----

/// Build HNSHK:n:4 with PinTan signature parameters.
pub(crate) fn hnshk(
    segment_number: u16,
    security_function: &str,
    security_reference: u32,
    blz: &str,
    user_id: &str,
    system_id: &str,
) -> Vec<DEG> {
    // let id_type = if system_id == "0" { "0" } else { "1" };
    vec![
        seg_header("HNSHK", segment_number, 4),
        deg(vec![de_text("PIN"), de_text(pin_version(security_function))]),
        // Security function (e.g. "999" for one-step, "912" for pushTAN)
        deg1(de_text(security_function)),
        // Security reference (random number linking HNSHK <-> HNSHA)
        deg1(de_num(security_reference)),
        // Security application area: 1 = SHM
        deg1(de_text("1")),
        // Security role: 1 = ISS
        deg1(de_text("1")),
        // Security identification: role=2(MS), cid=empty, identifier=system_id
        deg(vec![de_text("2"), de_empty(), de_text(system_id)]),
        // Security reference number: 1
        deg1(de_text("1")),
        // Security timestamp: type=1 (STS), date (YYYYMMDD), time (HHMMSS)
        {
            let now = Local::now();
            deg(vec![
                de_text("1"),
                de_text(&now.format("%Y%m%d").to_string()),
                de_text(&now.format("%H%M%S").to_string()),
            ])
        },
        // Hash algorithm: dummy (usage=1, alg=999, param=1)
        deg(vec![de_text("1"), de_text("999"), de_text("1")]),
        // Signature algorithm: dummy (usage=6, alg=10, mode=16)
        deg(vec![de_text("6"), de_text("10"), de_text("16")]),
        // Key name: country:blz:user_id:S(signing):0:0
        deg(vec![
            de_text("280"),
            de_text(blz),
            de_text(user_id),
            de_text("S"),
            de_text("0"),
            de_text("0"),
        ]),
    ]
}

// ---- HNSHA (Signaturabschluss) - Signature Trailer, version 2 ----

/// Build HNSHA:n:2 with PIN and optional TAN.
pub(crate) fn hnsha(
    segment_number: u16,
    security_reference: u32,
    pin: &str,
    tan: Option<&str>,
) -> Vec<DEG> {
    let mut user_sig_elements = vec![de_text(pin)];
    if let Some(t) = tan {
        // For empty TAN (after decoupled confirmation), force an empty-but-present field.
        // de_text("") returns DataElement::Empty which the serializer omits entirely.
        // We need DataElement::Text("") to produce the ':' separator in the output.
        if t.is_empty() {
            user_sig_elements.push(crate::parser::DataElement::Text(String::new()));
        } else {
            user_sig_elements.push(de_text(t));
        }
    }
    vec![
        seg_header("HNSHA", segment_number, 2),
        // Security reference (must match HNSHK)
        deg1(de_num(security_reference)),
        // Validation result: empty
        deg1(de_empty()),
        // User defined signature: PIN[:TAN]
        deg(user_sig_elements),
    ]
}

// ---- HKIDN (Identifikation) - version 2 ----

pub(crate) fn hkidn(segment_number: u16, blz: &str, user_id: &str, system_id: &str) -> Vec<DEG> {
    vec![
        seg_header("HKIDN", segment_number, 2),
        // Bank identifier: country(280):blz
        deg(vec![de_text("280"), de_text(blz)]),
        // Customer ID
        deg1(de_text(user_id)),
        // System ID (0 = not yet assigned)
        deg1(de_text(system_id)),
        // System ID required: 1
        deg1(de_text("1")),
    ]
}

// ---- HKVVB (Verarbeitungsvorbereitung) - Processing Preparation, version 3 ----

pub(crate) fn hkvvb(
    segment_number: u16,
    bpd_version: u16,
    upd_version: u16,
    product_id: &str,
) -> Vec<DEG> {
    vec![
        seg_header("HKVVB", segment_number, 3),
        // BPD version (0 = request full BPD)
        deg1(de_num(bpd_version)),
        // UPD version (0 = request full UPD)
        deg1(de_num(upd_version)),
        // Dialog language: 1 = German
        deg1(de_text("1")),
        // Product ID
        deg1(de_text(product_id)),
        // Product version
        deg1(de_text("1.0")),
    ]
}

// ---- HKSYN (Synchronisierung) - Synchronization, version 3 ----

/// Build HKSYN:n:3 to request a new system ID.
pub(crate) fn hksyn(segment_number: u16) -> Vec<DEG> {
    vec![
        seg_header("HKSYN", segment_number, 3),
        // Synchronization mode: 0 = request new system ID
        deg1(de_text("0")),
    ]
}

// ---- HKEND (Dialogende) - Dialog End, version 1 ----

pub(crate) fn hkend(segment_number: u16, dialog_id: &str) -> Vec<DEG> {
    vec![
        seg_header("HKEND", segment_number, 1),
        deg1(de_text(dialog_id)),
    ]
}

// ---- HKTAN (TAN-Verfahren) - TAN Segment, version 6/7 ----

/// Build HKTAN for process 4 (request challenge) — used in dialog init.
pub(crate) fn hktan_process4(
    segment_number: u16,
    version: u16,
    segment_type: &str,
    tan_medium_name: Option<&str>,
) -> Vec<DEG> {
    let mut degs = vec![
        seg_header("HKTAN", segment_number, version),
        // TAN process: 4 = request challenge
        deg1(de_text("4")),
        // Segment type (e.g. "HKIDN")
        deg1(de_text(segment_type)),
    ];

    if version >= 6 {
        // For v6+: empty fields until tan_medium_name
        // account, order_hash_value, order_reference, further_tan_follows, cancel_order
        degs.push(deg1(de_empty())); // account (not used)
        degs.push(deg1(de_empty())); // order_hash_value
        degs.push(deg1(de_empty())); // order_reference
        degs.push(deg1(de_empty())); // further_tan_follows (must not be populated for process 4)
        degs.push(deg1(de_empty())); // cancel_order
    }

    if let Some(name) = tan_medium_name {
        // For v6+: skip some fields to reach tan_medium_name
        if version >= 6 {
            degs.push(deg1(de_empty())); // sms_charge_account
            degs.push(deg1(de_empty())); // challenge_class
            degs.push(deg1(de_empty())); // challenge_class_params
        }
        degs.push(deg1(de_text(name)));
    }

    degs
}

/// Build HKTAN for process 2 (submit TAN) — completing a two-step operation.
pub(crate) fn hktan_process2(
    segment_number: u16,
    version: u16,
    task_reference: &str,
    tan_medium_name: Option<&str>,
) -> Vec<DEG> {
    let mut degs = vec![
        seg_header("HKTAN", segment_number, version),
        // TAN process: 2 = submit TAN
        deg1(de_text("2")),
    ];

    if version >= 6 {
        degs.push(deg1(de_empty())); // segment_type (not needed for process 2)
        degs.push(deg1(de_empty())); // account
        degs.push(deg1(de_empty())); // order_hash_value
        degs.push(deg1(de_text(task_reference))); // task reference (from HITAN)
        degs.push(deg1(de_bool(false))); // further_tan_follows = N
        degs.push(deg1(de_empty())); // cancel_order
    } else {
        degs.push(deg1(de_empty())); // segment_type
        degs.push(deg1(de_empty())); // account
        degs.push(deg1(de_text(task_reference))); // task reference
        degs.push(deg1(de_bool(false))); // further_tan_follows
    }

    if let Some(name) = tan_medium_name {
        if version >= 6 {
            degs.push(deg1(de_empty())); // sms_charge_account
            degs.push(deg1(de_empty())); // challenge_class
            degs.push(deg1(de_empty())); // challenge_class_params
        }
        degs.push(deg1(de_text(name)));
    }

    degs
}

/// Build HKTAN for process S (decoupled polling).
pub(crate) fn hktan_process_s(
    segment_number: u16,
    version: u16,
    task_reference: &str,
    tan_medium_name: Option<&str>,
) -> Vec<DEG> {
    let mut degs = vec![
        seg_header("HKTAN", segment_number, version),
        // TAN process: S = decoupled status check
        deg1(de_text("S")),
    ];

    if version >= 6 {
        degs.push(deg1(de_empty())); // segment_type
        degs.push(deg1(de_empty())); // account
        degs.push(deg1(de_empty())); // order_hash_value
        degs.push(deg1(de_text(task_reference))); // task reference
        degs.push(deg1(de_bool(false))); // further_tan_follows
        degs.push(deg1(de_empty())); // cancel_order
    } else {
        degs.push(deg1(de_empty()));
        degs.push(deg1(de_empty()));
        degs.push(deg1(de_text(task_reference)));
        degs.push(deg1(de_bool(false)));
    }

    if let Some(name) = tan_medium_name {
        if version >= 6 {
            degs.push(deg1(de_empty()));
            degs.push(deg1(de_empty()));
            degs.push(deg1(de_empty()));
        }
        degs.push(deg1(de_text(name)));
    }

    degs
}

// ---- HKTAB (TAN-Medium anfordern) - TAN Media List Request, version 4/5 ----

/// Build HKTAB to request the list of registered TAN media (devices).
/// Returns HITAB response with device names needed for pushTAN.
pub(crate) fn hktab(segment_number: u16, version: u16) -> Vec<DEG> {
    vec![
        seg_header("HKTAB", segment_number, version),
        // TAN medium class: A = all
        deg1(de_text("A")),
    ]
}

// ---- HKSPA (SEPA-Kontoverbindung anfordern) - SEPA Account Info, version 1-3 ----

pub(crate) fn hkspa(segment_number: u16, version: u16) -> Vec<DEG> {
    vec![seg_header("HKSPA", segment_number, version)]
}


// ---- HKSAL (Saldenabfrage) - Balance Request, version 5-7 ----

/// Build HKSAL for a specific SEPA account. Version 7 uses international account (IBAN/BIC).
pub(crate) fn hksal(
    segment_number: u16,
    version: u16,
    iban: &str,
    bic: &str,
    touchdown: Option<&str>,
) -> Vec<DEG> {
    let mut degs = if version >= 6 {
        // Version 6+: international account (KTI)
        vec![
            seg_header("HKSAL", segment_number, version),
            Kti::new(iban, bic).to_deg(),
            deg1(de_text("N")),
        ]
    } else {
        // Version 5: national account format (KTO) — account_number + BLZ, not IBAN + BIC
        let (account_number, blz) = extract_de_iban_parts(iban);
        vec![
            seg_header("HKSAL", segment_number, version),
            deg(vec![
                de_text(&account_number),
                de_empty(),
                de_text("280"),
                de_text(&blz),
            ]),
            deg1(de_text("N")),
        ]
    };

    // Max entries (optional)
    degs.push(deg1(de_empty()));

    // Touchdown point
    if let Some(td) = touchdown {
        degs.push(deg1(de_text(td)));
    }

    degs
}

// ---- HKKAZ (Kontoumsätze anfordern) - Statement Request (MT940), version 5-7 ----

pub(crate) fn hkkaz(
    segment_number: u16,
    version: u16,
    iban: &str,
    bic: &str,
    start_date: NaiveDate,
    end_date: NaiveDate,
    touchdown: Option<&str>,
) -> Vec<DEG> {
    let mut degs = if version >= 6 {
        vec![
            seg_header("HKKAZ", segment_number, version),
            Kti::new(iban, bic).to_deg(),
            deg1(de_text("N")),
            deg1(de_date(start_date)),
            deg1(de_date(end_date)),
        ]
    } else {
        // Version 5: national account format (KTO) — account_number + BLZ, not IBAN + BIC
        let (account_number, blz) = extract_de_iban_parts(iban);
        vec![
            seg_header("HKKAZ", segment_number, version),
            deg(vec![
                de_text(&account_number),
                de_empty(),
                de_text("280"),
                de_text(&blz),
            ]),
            deg1(de_text("N")),
            deg1(de_date(start_date)),
            deg1(de_date(end_date)),
        ]
    };

    // Max entries
    degs.push(deg1(de_empty()));

    // Touchdown
    if let Some(td) = touchdown {
        degs.push(deg1(de_text(td)));
    }

    degs
}

// ---- HKWPD (Wertpapierdepotaufstellung) - Securities Holdings Request, version 1-7 ----

/// Build HKWPD to request the securities depot listing for a SEPA account.
/// HKWPD returns HIWPD response with depot positions.
///
/// FinTS spec structure:
///   DEG0 = header (HKWPD:seg_num:version)
///   DEG1 = account connection (KTI: IBAN:BIC)
///   DEG2 = currency (optional, e.g. "EUR" — request prices in this currency)
///   DEG3 = quality of data (1=current, 2=cached/last known — optional)
///   DEG4 = max entries (optional)
///   DEG5 = touchdown point (optional, for pagination)
pub(crate) fn hkwpd(
    segment_number: u16,
    version: u16,
    iban: &str,
    bic: &str,
    currency: Option<&str>,
    touchdown: Option<&str>,
) -> Vec<DEG> {
    let mut degs = if version >= 6 {
        // Version 6+: international account (KTI)
        vec![
            seg_header("HKWPD", segment_number, version),
            Kti::new(iban, bic).to_deg(),
        ]
    } else {
        // Older versions: national account format
        vec![
            seg_header("HKWPD", segment_number, version),
            deg(vec![
                de_text(iban),
                de_empty(),
                de_text("280"),
                de_text(bic),
            ]),
        ]
    };

    // Currency (optional)
    degs.push(deg1(if let Some(cur) = currency {
        de_text(cur)
    } else {
        de_empty()
    }));

    // Quality of data (optional) — request current data
    degs.push(deg1(de_empty()));

    // Max entries (optional)
    degs.push(deg1(de_empty()));

    // Touchdown point (optional)
    if let Some(td) = touchdown {
        degs.push(deg1(de_text(td)));
    }

    degs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serializer::{serialize_deg, serialize_segment};

    #[test]
    fn kti_produces_two_data_elements() {
        let kti = Kti::new("DE04120300001084174299", "BYLADEM1001");
        let deg = kti.to_deg();
        // KTI DEG: IBAN:BIC (optional trailing fields omitted)
        assert_eq!(deg.0.len(), 2, "KTI DEG must have exactly 2 data elements");
        assert_eq!(deg.get_str(0), "DE04120300001084174299");
        assert_eq!(deg.get_str(1), "BYLADEM1001");
    }

    #[test]
    fn kti_serializes_as_iban_colon_bic() {
        let kti = Kti::new("DE04120300001084174299", "BYLADEM1001");
        let bytes = serialize_deg(&kti.to_deg()).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        // Wire format: IBAN:BIC
        assert_eq!(wire, "DE04120300001084174299:BYLADEM1001");
    }

    #[test]
    fn hksal_v7_wire_format() {
        let degs = hksal(3, 7, "DE04120300001084174299", "BYLADEM1001", None);
        let bytes = serialize_segment(&degs).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert_eq!(wire, "HKSAL:3:7+DE04120300001084174299:BYLADEM1001+N'");
    }

    #[test]
    fn hkkaz_v7_wire_format() {
        let start = chrono::NaiveDate::from_ymd_opt(2025, 3, 29).unwrap();
        let end = chrono::NaiveDate::from_ymd_opt(2026, 3, 29).unwrap();
        let degs = hkkaz(
            3,
            7,
            "DE04120300001084174299",
            "BYLADEM1001",
            start,
            end,
            None,
        );
        let bytes = serialize_segment(&degs).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert_eq!(
            wire,
            "HKKAZ:3:7+DE04120300001084174299:BYLADEM1001+N+20250329+20260329'"
        );
    }

    #[test]
    fn hkwpd_v7_wire_format() {
        let degs = hkwpd(3, 7, "DE04120300001084174299", "BYLADEM1001", None, None);
        let bytes = serialize_segment(&degs).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert_eq!(wire, "HKWPD:3:7+DE04120300001084174299:BYLADEM1001'");
    }

    #[test]
    fn hkwpd_v7_with_currency() {
        let degs = hkwpd(
            3,
            7,
            "DE04120300001084174299",
            "BYLADEM1001",
            Some("EUR"),
            None,
        );
        let bytes = serialize_segment(&degs).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert_eq!(wire, "HKWPD:3:7+DE04120300001084174299:BYLADEM1001+EUR'");
    }

    #[test]
    fn hkwpd_v7_with_touchdown() {
        let degs = hkwpd(
            3,
            7,
            "DE04120300001084174299",
            "BYLADEM1001",
            None,
            Some("TOUCH123"),
        );
        let bytes = serialize_segment(&degs).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        // DEGs: header + KTI + currency(empty) + quality(empty) + max_entries(empty) + touchdown
        assert_eq!(
            wire,
            "HKWPD:3:7+DE04120300001084174299:BYLADEM1001++++TOUCH123'"
        );
    }

    #[test]
    #[should_panic(expected = "IBAN must not be empty")]
    fn kti_panics_on_empty_iban() {
        Kti::new("", "BYLADEM1001");
    }

    #[test]
    #[should_panic(expected = "BIC must not be empty")]
    fn kti_panics_on_empty_bic() {
        Kti::new("DE04120300001084174299", "");
    }
}
