//! FinTS 3.0 Protocol State Machine (spec-aligned).
//!
//! Implements the dialog lifecycle as defined in FinTS 3.0 Formals (2017-10-06)
//! and PIN/TAN Security (2020-07-10).
//!
//! ## Dialog types (spec Chapter C)
//!
//! - **Synchronization dialog**: HKIDN + HKVVB + HKSYN → get system_id → HKEND.
//!   Marked by presence of HKSYN. Business segments are forbidden (banks return 9110).
//! - **Normal dialog**: HKIDN + HKVVB [+ HKTAN:4] → [TAN confirmation] → business ops → HKEND.
//!
//! ## State machine (spec Chapter C, Section 6)
//!
//! ```text
//!   Dialog<New>
//!       │
//!       ├── sync()           → (Dialog<Synced>, Response)      [sync dialog]
//!       │
//!       └── init()           → InitResult                      [normal dialog]
//!             ├── Opened(Dialog<Open>)                            response 0010/0020
//!             └── TanRequired(Dialog<TanPending>, TanChallenge)   response 0030/3955
//!
//!   Dialog<Synced>
//!       └── end()            → (BankParams, String)             [get params + system_id]
//!
//!   Dialog<Open>
//!       ├── send()           → SendResult                       [business segment]
//!       │     ├── Success(Response)                               response 0020
//!       │     ├── NeedTan(Dialog<TanPending>, TanChallenge)       response 0030/3955
//!       │     └── Touchdown(Response, String)                     response 3040
//!       └── end()            → ()                               [HKEND]
//!
//!   Dialog<TanPending>
//!       ├── poll()           → PollResult                       [HKTAN process S]
//!       │     ├── Confirmed(Dialog<Open>, Response)               response 0020
//!       │     └── Pending(Dialog<TanPending>)                     response 3955/3956
//!       ├── submit_tan()     → (Dialog<Open>, Response)         [HKTAN process 2]
//!       └── cancel()         → ()                               [HKEND]
//! ```

use std::collections::HashMap;
use std::marker::PhantomData;
use tracing::{debug, info, warn};

use chrono::NaiveDate;

use crate::error::{FinTSError, Result};
use crate::message;
use crate::parser::{self, RawSegment, DEG};
use crate::segments::response::*;
use crate::transport::FinTSConnection;
use crate::types::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Typestate markers (per spec dialog states)
// ═══════════════════════════════════════════════════════════════════════════════

/// Dialog not yet started. Can transition to `Synced` or `Open`/`TanPending`.
#[derive(Debug)]
pub struct New;
/// Synchronization dialog: system_id obtained, BPD/UPD cached. No business ops allowed.
#[derive(Debug)]
pub struct Synced;
/// Dialog is open and authenticated. Business segments can be sent.
#[derive(Debug)]
pub struct Open;
/// A TAN challenge is pending (either from init or from a business segment).
#[derive(Debug)]
pub struct TanPending;

// ═══════════════════════════════════════════════════════════════════════════════
// Typed business segments — replaces raw Vec<DEG> at all internal boundaries
// ═══════════════════════════════════════════════════════════════════════════════

/// A typed FinTS business segment. Every field is validated at construction.
/// This is the ONLY way to construct segments within the crate — raw DEG
/// builders are never called directly from protocol or workflow code.
#[derive(Debug, Clone)]
pub(crate) enum Segment {
    /// HKIDN: Identifikation (dialog init)
    Identify { blz: Blz, user_id: UserId, system_id: SystemId },
    /// HKVVB: Verarbeitungsvorbereitung
    ProcessPrep { bpd_version: u16, upd_version: u16, product_id: ProductId },
    /// HKSYN: Synchronisierung (get system_id)
    Sync,
    /// HKSAL: Saldenabfrage (balance request)
    Balance { account: Account },
    /// HKKAZ: Kontoumsätze (transaction request)
    Transactions {
        account: Account,
        start_date: NaiveDate,
        end_date: NaiveDate,
        touchdown: Option<TouchdownPoint>,
    },
    /// HKWPD: Wertpapierdepotaufstellung (securities holdings request)
    Holdings {
        account: Account,
        currency: Option<Currency>,
        touchdown: Option<TouchdownPoint>,
    },
    /// HKTAN process 4: initiate TAN for a referenced segment
    TanProcess4 { reference_seg: SegmentRef, tan_medium: Option<TanMediumName> },
    /// HKTAN process S: poll decoupled TAN status
    TanPollDecoupled { task_reference: TaskReference, tan_medium: Option<TanMediumName> },
    /// HKTAN process 2: submit TAN response
    TanProcess2 { task_reference: TaskReference, tan_medium: Option<TanMediumName> },
    /// HKEND: dialog end
    End { dialog_id: DialogId },
}

impl Segment {
    /// Convert to raw DEGs using bank parameters for version selection.
    pub(crate) fn to_degs(&self, params: &BankParams) -> Vec<DEG> {
        use crate::segments::builder::*;
        match self {
            Segment::Identify { blz, user_id, system_id } => {
                hkidn(0, blz.as_str(), user_id.as_str(), system_id.as_str())
            }
            Segment::ProcessPrep { bpd_version, upd_version, product_id } => {
                hkvvb(0, *bpd_version, *upd_version, product_id.as_str())
            }
            Segment::Sync => {
                hksyn(0)
            }
            Segment::Balance { account } => {
                let version = params.supported_version("HISALS", 7).max(5);
                hksal(0, version, account.iban(), account.bic(), None)
            }
            Segment::Transactions { account, start_date, end_date, touchdown } => {
                let version = params.supported_version("HIKAZS", 7).max(5);
                hkkaz(0, version, account.iban(), account.bic(), *start_date, *end_date, touchdown.as_ref().map(|t| t.as_str()))
            }
            Segment::Holdings { account, currency, touchdown } => {
                let version = params.supported_version("HIWPDS", 7).max(1);
                hkwpd(0, version, account.iban(), account.bic(), currency.as_ref().map(|c| c.as_str()), touchdown.as_ref().map(|t| t.as_str()))
            }
            Segment::TanProcess4 { reference_seg, tan_medium } => {
                let version = params.hktan_version();
                hktan_process4(0, version, reference_seg.as_str(), tan_medium.as_ref().map(|t| t.as_str()))
            }
            Segment::TanPollDecoupled { task_reference, tan_medium } => {
                let version = params.hktan_version();
                hktan_process_s(0, version, task_reference.as_str(), tan_medium.as_ref().map(|t| t.as_str()))
            }
            Segment::TanProcess2 { task_reference, tan_medium } => {
                let version = params.hktan_version();
                hktan_process2(0, version, task_reference.as_str(), tan_medium.as_ref().map(|t| t.as_str()))
            }
            Segment::End { dialog_id } => {
                hkend(0, dialog_id.as_str())
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Result of dialog init — response-driven transition
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of `Dialog::init()`. Per the spec, the bank either accepts the dialog
/// (0010/0020) or requires SCA (0030/3955).
pub enum InitResult {
    /// Dialog opened, no TAN needed. Ready for business segments.
    Opened(Dialog<Open>, Response),
    /// Bank requires TAN on init (SCA). Must confirm before business ops.
    TanRequired(Dialog<TanPending>, TanChallenge, Response),
}

// ═══════════════════════════════════════════════════════════════════════════════
// Result of sending a business segment — response-driven transition
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of `Dialog<Open>::send()`. Per the spec, three outcomes are possible.
pub enum SendResult {
    /// 0020: Order executed. Response contains the result data (HISAL, HIKAZ, etc.).
    Success(Response),
    /// 0030/3955: TAN required for this operation. Dialog transitions to TanPending.
    NeedTan(Dialog<TanPending>, TanChallenge, Response),
    /// 3040: More data available (pagination). Response contains partial data
    /// plus a touchdown point string for the next request.
    Touchdown(Response, String),
}

// ═══════════════════════════════════════════════════════════════════════════════
// Result of polling TAN — response-driven transition
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of `Dialog<TanPending>::poll()`.
pub enum PollResult {
    /// TAN confirmed. Dialog returns to Open state.
    Confirmed(Dialog<Open>, Response),
    /// TAN still pending (3955/3956). Dialog remains in TanPending.
    Pending(Dialog<TanPending>),
}

// ═══════════════════════════════════════════════════════════════════════════════
// Parsed bank response
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed response from the bank after sending a message.
#[derive(Debug)]
pub struct Response {
    /// All segments from the response (including inner HNVSD segments).
    pub segments: Vec<RawSegment>,
    /// Global response codes (from HIRMG).
    pub global_codes: Vec<ResponseCode>,
    /// Segment-specific response codes (from HIRMS).
    pub segment_codes: Vec<ResponseCode>,
}

impl Response {
    pub fn find_segments(&self, seg_type: &str) -> Vec<&RawSegment> {
        self.segments.iter().filter(|s| s.segment_type() == seg_type).collect()
    }

    pub fn find_segment(&self, seg_type: &str) -> Option<&RawSegment> {
        self.segments.iter().find(|s| s.segment_type() == seg_type)
    }

    pub fn all_codes(&self) -> impl Iterator<Item = &ResponseCode> {
        self.global_codes.iter().chain(self.segment_codes.iter())
    }

    /// 0030 = order received, TAN required.
    pub fn needs_tan(&self) -> bool {
        self.all_codes().any(|c| c.is_tan_required() || c.is_decoupled())
    }

    /// 3955 = decoupled TAN (pushTAN initiated).
    pub fn is_decoupled(&self) -> bool {
        self.all_codes().any(|c| c.is_decoupled())
    }

    /// 3955/3956 = decoupled TAN still pending.
    pub fn is_decoupled_pending(&self) -> bool {
        self.all_codes().any(|c| c.is_decoupled_pending())
    }

    /// 3076 = no strong authentication required (SCA exemption).
    pub fn has_sca_exemption(&self) -> bool {
        self.all_codes().any(|c| c.kind == ResponseCodeKind::ScaExemption)
    }

    /// 3040 = more data available (touchdown/pagination).
    /// Returns the touchdown point if found.
    pub fn touchdown(&self) -> Option<TouchdownPoint> {
        find_touchdown(&self.segment_codes)
            .or_else(|| find_touchdown(&self.global_codes))
    }

    /// Extract HITAN challenge from response.
    pub fn get_tan_challenge(&self) -> Option<TanChallenge> {
        if let Some(hitan) = self.find_segment("HITAN") {
            let (task_ref, challenge, hhduc) = parse_hitan(hitan);
            if !task_ref.is_empty() || !challenge.is_empty() {
                return Some(TanChallenge {
                    challenge: ChallengeText::new(challenge),
                    challenge_hhduc: hhduc.map(HhdUcData),
                    task_reference: TaskReference::new(task_ref),
                    decoupled: self.is_decoupled(),
                });
            }
        }
        None
    }

    /// Check for fatal errors. Returns `Ok(())` if no errors.
    pub fn check_errors(&self) -> Result<()> {
        for code in self.all_codes() {
            match &code.kind {
                ResponseCodeKind::PinWrong => return Err(FinTSError::PinWrong),
                ResponseCodeKind::AccountLocked => return Err(FinTSError::AccountLocked),
                k if k.is_error() => return Err(FinTSError::BankError {
                    kind: code.kind.clone(),
                    message: code.text.clone(),
                }),
                _ => {}
            }
        }
        Ok(())
    }

    /// Extract allowed TAN security functions from code 3920.
    pub fn allowed_security_functions(&self) -> Vec<SecurityFunction> {
        extract_allowed_security_functions(&self.segment_codes)
            .into_iter()
            .chain(extract_allowed_security_functions(&self.global_codes))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAN challenge
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TanChallenge {
    pub challenge: ChallengeText,
    pub challenge_hhduc: Option<HhdUcData>,
    pub task_reference: TaskReference,
    pub decoupled: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Bank parameters
// ═══════════════════════════════════════════════════════════════════════════════

/// Cached bank and user parameters discovered during sync/init.
#[derive(Debug, Clone)]
pub struct BankParams {
    pub bpd_version: u16,
    pub upd_version: u16,
    pub bpd_segments: Vec<RawSegment>,
    pub upd_segments: Vec<RawSegment>,
    pub tan_methods: Vec<TanMethod>,
    pub selected_security_function: SecurityFunction,
    pub selected_tan_medium: Option<TanMediumName>,
    pub accounts_from_upd: Vec<SepaAccount>,
    pub operation_tan_required: HashMap<SegmentType, bool>,
    pub allowed_security_functions: Vec<SecurityFunction>,
    pub preferred_security_function: Option<SecurityFunction>,
}

impl BankParams {
    pub fn new() -> Self {
        Self {
            bpd_version: 0, upd_version: 0,
            bpd_segments: Vec::new(), upd_segments: Vec::new(),
            tan_methods: Vec::new(),
            selected_security_function: SecurityFunction::pin_only(),
            selected_tan_medium: None,
            accounts_from_upd: Vec::new(),
            operation_tan_required: HashMap::new(),
            allowed_security_functions: Vec::new(),
            preferred_security_function: None,
        }
    }

    /// Ingest BPD/UPD/HITANS/HIPINS/HISYN from a response.
    pub fn ingest_response(&mut self, response: &Response, system_id: &mut SystemId) {
        for seg in &response.segments {
            let stype = seg.segment_type();
            match stype {
                "HIBPA" => self.bpd_version = parse_hibpa_version(seg),
                "HITANS" => self.tan_methods.extend(parse_hitans(seg)),
                "HIPINS" => {
                    let m = parse_hipins(seg);
                    if !m.is_empty() {
                        info!("[FinTS] HIPINS: {} operation rules", m.len());
                        self.operation_tan_required.extend(m);
                    }
                }
                "HIUPA" => self.upd_version = parse_hiupa_version(seg),
                "HIUPD" => {
                    self.upd_segments.push(seg.clone());
                    if let Some(acc) = parse_hiupd(seg) {
                        self.accounts_from_upd.push(acc);
                    }
                }
                "HISYN" => {
                    let sid = parse_hisyn_system_id(seg);
                    if !sid.is_empty() {
                        info!("[FinTS] System ID: {}", sid);
                        *system_id = SystemId::new(sid);
                    }
                }
                _ => {
                    if stype.starts_with("HI") && stype.len() >= 5 && stype.ends_with('S') {
                        self.bpd_segments.push(seg.clone());
                    }
                }
            }
        }
        let allowed = response.allowed_security_functions();
        if !allowed.is_empty() {
            self.allowed_security_functions = allowed;
        }
    }

    /// Does the given operation require TAN (per HIPINS)? Default: true (safe).
    pub fn needs_tan(&self, segment_type: &SegmentType) -> bool {
        self.operation_tan_required.get(segment_type).copied().unwrap_or(true)
    }

    /// HKTAN version for the selected TAN method.
    pub fn hktan_version(&self) -> u16 {
        self.tan_methods.iter()
            .find(|m| m.security_function == self.selected_security_function)
            .map(|m| m.hktan_version)
            .unwrap_or(7)
    }

    /// Highest supported version for a segment type in BPD.
    pub fn supported_version(&self, param_segment_type: &str, max_version: u16) -> u16 {
        let v = find_highest_segment_version(&self.bpd_segments, param_segment_type, max_version);
        let result = if v == 0 { max_version } else { v };
        info!("[FinTS] BPD lookup: {} → found v{} (BPD has v{}, max={})",
            param_segment_type, result, v, max_version);
        result
    }

    /// Select the best security function from 3920 allowed list.
    pub fn select_security_function(&mut self) {
        let allowed = &self.allowed_security_functions;
        if allowed.is_empty() { return; }

        if let Some(ref pref) = self.preferred_security_function {
            if allowed.contains(pref) {
                self.selected_security_function = pref.clone();
                return;
            }
        }

        let pin_only = SecurityFunction::pin_only();
        let methods = &self.tan_methods;
        let chosen = allowed.iter()
            .filter(|sf| *sf != &pin_only)
            .max_by_key(|sf| {
                methods.iter().find(|m| &m.security_function == *sf)
                    .map(|m| if m.is_decoupled { 2i32 } else { 1 })
                    .unwrap_or(0)
            });

        if let Some(sf) = chosen {
            info!("[FinTS] Selected security function: {}", sf);
            self.selected_security_function = sf.clone();
        }
    }

    pub fn is_decoupled(&self) -> bool {
        self.tan_methods.iter()
            .find(|m| m.security_function == self.selected_security_function)
            .map(|m| m.is_decoupled)
            .unwrap_or(false)
    }

    pub fn needs_tan_medium(&self) -> bool {
        self.tan_methods.iter()
            .find(|m| m.security_function == self.selected_security_function)
            .map(|m| m.needs_tan_medium)
            .unwrap_or(false)
    }

    pub fn decoupled_params(&self) -> (u64, u64, u32) {
        self.tan_methods.iter()
            .find(|m| m.security_function == self.selected_security_function)
            .map(|m| {
                let first = if m.wait_before_first_poll > 0 { m.wait_before_first_poll as u64 } else { 5 };
                let next = if m.wait_before_next_poll > 0 { m.wait_before_next_poll as u64 } else { 5 };
                let max = if m.decoupled_max_polls > 0 { m.decoupled_max_polls as u32 } else { 20 };
                (first, next, max)
            })
            .unwrap_or((5, 5, 20))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Dialog<S> — the typestate dialog
// ═══════════════════════════════════════════════════════════════════════════════

pub struct Dialog<S: std::fmt::Debug> {
    connection: FinTSConnection,
    blz: Blz,
    user_id: UserId,
    pin: Pin,
    system_id: SystemId,
    product_id: ProductId,
    dialog_id: DialogId,
    message_number: u16,
    pub params: BankParams,
    _state: PhantomData<S>,
}

impl<S: std::fmt::Debug> std::fmt::Debug for Dialog<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dialog")
            .field("blz", &self.blz)
            .field("user_id", &self.user_id)
            .field("system_id", &self.system_id)
            .field("dialog_id", &self.dialog_id)
            .field("message_number", &self.message_number)
            .field("state", &std::any::type_name::<S>())
            .finish()
    }
}

// Note: Pin intentionally Debug-redacted (shows "Pin(****)")

// ── Shared internals (all states) ───────────────────────────────────────────

impl<S: std::fmt::Debug> Dialog<S> {
    pub fn system_id(&self) -> &SystemId { &self.system_id }
    pub fn bank_params(&self) -> &BankParams { &self.params }
    pub fn bank_params_mut(&mut self) -> &mut BankParams { &mut self.params }

    /// Build the standard HKIDN segment for this dialog.
    fn identify_segment(&self) -> Segment {
        Segment::Identify {
            blz: self.blz.clone(),
            user_id: self.user_id.clone(),
            system_id: self.system_id.clone(),
        }
    }

    /// Build the standard HKVVB segment for this dialog.
    fn process_prep_segment(&self) -> Segment {
        Segment::ProcessPrep {
            bpd_version: self.params.bpd_version,
            upd_version: self.params.upd_version,
            product_id: self.product_id.clone(),
        }
    }

    /// Send typed segments with PIN but no TAN.
    async fn send_segments(&mut self, segments: &[Segment]) -> Result<Response> {
        let msg_bytes = message::build_message_from_typed(
            &self.dialog_id, self.message_number,
            &self.blz, &self.user_id, &self.system_id, &self.pin,
            &self.params.selected_security_function,
            segments, &self.params,
        )?;

        let msg_str = String::from_utf8_lossy(&msg_bytes);
        let redacted = msg_str.replace(self.pin.as_str(), "***PIN***");
        info!("[FinTS] Outgoing ({} bytes): {}", msg_bytes.len(), &redacted[..redacted.len().min(500)]);

        self.message_number += 1;
        let response_bytes = self.connection.send(&msg_bytes).await?;
        parse_response(&response_bytes, self.message_number - 1)
    }

    /// Send typed segments with an explicit TAN value in HNSHA.
    async fn send_segments_with_tan(&mut self, segments: &[Segment], tan: &str) -> Result<Response> {
        let msg_bytes = message::build_message_from_typed_with_tan(
            &self.dialog_id, self.message_number,
            &self.blz, &self.user_id, &self.system_id, &self.pin,
            tan, &self.params.selected_security_function,
            segments, &self.params,
        )?;
        self.message_number += 1;
        let response_bytes = self.connection.send(&msg_bytes).await?;
        parse_response(&response_bytes, self.message_number - 1)
    }

    async fn send_end(&mut self) -> Result<()> {
        if !self.dialog_id.is_assigned() { return Ok(()); }
        debug!("Ending dialog {}", self.dialog_id);
        let msg_bytes = message::build_end_message(
            &self.dialog_id, self.message_number,
            &self.blz, &self.user_id, &self.system_id, &self.pin,
            &self.params.selected_security_function,
            &self.params,
        )?;
        self.message_number += 1;
        let _ = self.connection.send(&msg_bytes).await;
        self.dialog_id = DialogId::unassigned();
        Ok(())
    }

    fn extract_dialog_id(&mut self, response: &Response) {
        if let Some(hnhbk) = response.find_segment("HNHBK") {
            let new_id = hnhbk.deg(3).get_str(0);
            if !new_id.is_empty() && new_id != "0" {
                self.dialog_id = DialogId::new(new_id);
            }
        }
    }

    fn transition<T: std::fmt::Debug>(self) -> Dialog<T> {
        Dialog {
            connection: self.connection, blz: self.blz, user_id: self.user_id,
            pin: self.pin, system_id: self.system_id, product_id: self.product_id,
            dialog_id: self.dialog_id, message_number: self.message_number,
            params: self.params, _state: PhantomData,
        }
    }
}

// ── Dialog<New> ─────────────────────────────────────────────────────────────

impl Dialog<New> {
    pub fn new(url: &str, blz: &Blz, user_id: &UserId, pin: &Pin, product_id: &ProductId) -> Result<Self> {
        Ok(Self {
            connection: FinTSConnection::new(url)?,
            blz: blz.clone(), user_id: user_id.clone(),
            pin: pin.clone(), system_id: SystemId::unassigned(),
            product_id: product_id.clone(),
            dialog_id: DialogId::unassigned(), message_number: 1,
            params: BankParams::new(), _state: PhantomData,
        })
    }

    pub fn with_system_id(mut self, system_id: &SystemId) -> Self {
        self.system_id = system_id.clone(); self
    }

    pub fn with_params(mut self, params: &BankParams) -> Self {
        self.params = params.clone(); self
    }
        
    pub fn with_security_function(mut self, function: SecurityFunction) -> Self {
        self.params.selected_security_function = function;
        self
    }

    pub fn with_tan_medium(mut self, medium: &TanMediumName) -> Self {
        self.params.selected_tan_medium = Some(medium.clone()); self
    }

    /// Synchronization dialog (spec: Initialisierung mit Synchronisierung).
    ///
    /// Sends HKIDN + HKVVB + HKSYN (mode=0 for new system_id).
    /// The bank responds with BPD, UPD, HITANS, HIPINS, and HISYN(system_id).
    /// This dialog is ONLY for synchronization — no business segments allowed.
    pub async fn sync(mut self) -> Result<(Dialog<Synced>, Response)> {
        info!("[FinTS] Sync dialog: BLZ={} user={} system_id={}", self.blz, self.user_id, self.system_id);

        let segments = [
            self.identify_segment(),
            self.process_prep_segment(),
            Segment::Sync,
        ];

        let response = self.send_segments(&segments).await?;
        self.extract_dialog_id(&response);
        self.params.ingest_response(&response, &mut self.system_id);
        self.params.select_security_function();

        // Check for fatal errors (sync dialog should not require TAN)
        if !response.needs_tan() {
            response.check_errors()?;
        }

        // Log all BPD parameter segments for diagnostics
        let bpd_summary: Vec<String> = self.params.bpd_segments.iter()
            .map(|s| format!("{}:v{}", s.segment_type(), s.segment_version()))
            .collect();
        info!("[FinTS] Sync complete: BPD v{}, {} TAN methods, system_id={}",
            self.params.bpd_version, self.params.tan_methods.len(), self.system_id);
        info!("[FinTS] BPD segments ({}): {}", bpd_summary.len(), bpd_summary.join(", "));

        Ok((self.transition(), response))
    }

    /// Normal dialog initialization (spec: Dialoginitialisierung).
    ///
    /// Sends HKIDN + HKVVB + HKTAN(process=4, ref=HKIDN).
    /// Response-driven: returns `InitResult::Opened` or `InitResult::TanRequired`
    /// based on the bank's response codes.
    pub async fn init(mut self) -> Result<InitResult> {
        let medium = self.params.selected_tan_medium.clone();
        info!("[FinTS] Init dialog: BLZ={} security_fn={}", self.blz, self.params.selected_security_function);

        let segments = [
            self.identify_segment(),
            self.process_prep_segment(),
            Segment::TanProcess4 { reference_seg: SegmentRef::new("HKIDN"), tan_medium: medium },
        ];

        let response = self.send_segments(&segments).await?;
        self.extract_dialog_id(&response);
        self.params.ingest_response(&response, &mut self.system_id);

        let allowed = response.allowed_security_functions();
        if !allowed.is_empty() {
            self.params.allowed_security_functions = allowed;
            self.params.select_security_function();
        }

        for c in response.all_codes() {
            info!("[FinTS] Init: {} - {}", c.code(), c.text);
        }

        // Response-driven transition per spec:
        if response.needs_tan() {
            if let Some(challenge) = response.get_tan_challenge() {
                // 0030/3955: TAN required on init → TanPending
                let challenge = TanChallenge {
                    decoupled: challenge.decoupled || self.params.is_decoupled(),
                    ..challenge
                };
                info!("[FinTS] Init requires TAN: decoupled={}", challenge.decoupled);
                return Ok(InitResult::TanRequired(self.transition(), challenge, response));
            }
        }

        // 0010/0020 or 3076: dialog opened, no TAN needed → Open
        response.check_errors()?;
        info!("[FinTS] Init opened without TAN");
        Ok(InitResult::Opened(self.transition(), response))
    }

    /// Initialize WITHOUT HKTAN — PIN-only. Used when bank doesn't require SCA.
    pub async fn init_no_tan(mut self) -> Result<(Dialog<Open>, Response)> {
        info!("[FinTS] Init (no HKTAN)");
        let segments = [
            self.identify_segment(),
            self.process_prep_segment(),
        ];

        let response = self.send_segments(&segments).await?;
        self.extract_dialog_id(&response);
        self.params.ingest_response(&response, &mut self.system_id);
        response.check_errors()?;
        Ok((self.transition(), response))
    }
}

// ── Dialog<Synced> ──────────────────────────────────────────────────────────

impl Dialog<Synced> {
    /// End the sync dialog. Returns bank params and system_id for use in normal dialogs.
    pub async fn end(mut self) -> Result<(BankParams, SystemId)> {
        self.send_end().await.ok();
        Ok((self.params, self.system_id))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Account — validated account identifier (IBAN + BIC, both required)
// ═══════════════════════════════════════════════════════════════════════════════

/// A validated bank account identifier (Kontoverbindung International).
///
/// Both IBAN and BIC are required and non-empty. This is enforced at
/// construction time — you cannot create an `Account` with a missing BIC.
/// All typed business operations on `Dialog<Open>` take `&Account`,
/// making it a compile error to pass raw strings that might be empty.
///
/// ```
/// use fints::protocol::Account;
///
/// // This works:
/// let acc = Account::new("DE89370400440532013000", "COBADEFFXXX").unwrap();
///
/// // This fails at construction time:
/// let bad = Account::new("DE89370400440532013000", "");
/// assert!(bad.is_err());
/// ```
#[derive(Debug, Clone)]
pub struct Account {
    iban: Iban,
    bic: Bic,
}

impl Account {
    /// Create a validated account. Returns `Err` if IBAN or BIC is empty.
    pub fn new(iban: &str, bic: &str) -> Result<Self> {
        if iban.is_empty() {
            return Err(FinTSError::Dialog("IBAN must not be empty".into()));
        }
        if bic.is_empty() {
            return Err(FinTSError::Dialog("BIC must not be empty. Please set the BIC in the account settings.".into()));
        }
        Ok(Self { iban: Iban::new(iban), bic: Bic::new(bic) })
    }

    pub fn iban(&self) -> &str { self.iban.as_str() }
    pub fn bic(&self) -> &str { self.bic.as_str() }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Typed business operation results
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of a balance request.
pub enum BalanceResult {
    /// Balance retrieved successfully.
    Success(AccountBalance),
    /// Bank requires TAN for this operation.
    NeedTan(TanChallenge),
    /// No balance data in response (unexpected but not fatal).
    Empty,
}

/// Result of a transaction request (single page).
pub struct TransactionPage {
    /// MT940 booked transaction data.
    pub booked: Mt940Data,
    /// MT940 pending transaction data.
    pub pending: Mt940Data,
    /// If Some, more data is available — call `transactions()` again with this value.
    pub touchdown: Option<TouchdownPoint>,
}

/// Result of a transaction request.
pub enum TransactionResult {
    /// Transaction data retrieved (may need more pages via touchdown).
    Success(TransactionPage),
    /// Bank requires TAN for this operation.
    NeedTan(TanChallenge),
}

/// Result of a single securities holdings request page.
pub struct HoldingsPage {
    /// Parsed securities positions.
    pub holdings: Vec<SecurityHolding>,
    /// If Some, more data is available — call `holdings()` again with this value.
    pub touchdown: Option<TouchdownPoint>,
}

/// Result of a holdings request.
pub enum HoldingsResult {
    /// Holdings data retrieved (may need more pages via touchdown).
    Success(HoldingsPage),
    /// Bank requires TAN for this operation.
    NeedTan(TanChallenge),
    /// No holdings data in response (depot may be empty or segment not supported).
    Empty,
}

// ── Dialog<Open> ─────────────────────────────────────────────────────────────

impl Dialog<Open> {
    /// Request account balance (HKSAL).
    ///
    /// Takes a validated `Account` — IBAN and BIC are guaranteed non-empty.
    /// Automatically selects the correct HKSAL version from BPD and bundles
    /// HKTAN:4 when HIPINS says TAN is required for this operation.
    pub async fn balance(&mut self, account: &Account) -> Result<BalanceResult> {
        let hksal = SegmentType::new("HKSAL");
        let needs_tan = self.params.needs_tan(&hksal);
        let mut segments = vec![
            Segment::Balance { account: account.clone() },
        ];
        if needs_tan {
            info!("[FinTS] balance: HKSAL + HKTAN:4 (HIPINS: TAN required)");
            segments.push(Segment::TanProcess4 {
                reference_seg: SegmentRef::new("HKSAL"),
                tan_medium: self.params.selected_tan_medium.clone(),
            });
        } else {
            info!("[FinTS] balance: HKSAL (HIPINS: PIN-only)");
        }

        let response = self.send_segments(&segments).await?;

        for c in response.all_codes() {
            if c.is_error() || c.is_warning() {
                info!("[FinTS] HKSAL: {} - {}", c.code(), c.text);
            }
        }

        // TAN required but no exemption
        if response.needs_tan() && !response.has_sca_exemption() {
            if let Some(challenge) = response.get_tan_challenge() {
                return Ok(BalanceResult::NeedTan(challenge));
            }
        }

        // Check errors
        response.check_errors()?;

        // Parse HISAL
        if let Some(hisal) = response.find_segment("HISAL") {
            if let Some(balance) = parse_hisal(hisal) {
                return Ok(BalanceResult::Success(balance));
            }
        }

        Ok(BalanceResult::Empty)
    }

    /// Request account transactions (HKKAZ) — single page.
    ///
    /// Takes a validated `Account`. For pagination, pass the `touchdown` value
    /// from a previous `TransactionPage` — pass `None` for the first request.
    /// HKTAN:4 is only bundled on the first request (not on touchdown pages).
    pub async fn transactions(
        &mut self,
        account: &Account,
        start_date: NaiveDate,
        end_date: NaiveDate,
        touchdown: Option<&TouchdownPoint>,
    ) -> Result<TransactionResult> {
        let is_first = touchdown.is_none();
        let hkkaz = SegmentType::new("HKKAZ");
        let needs_tan = self.params.needs_tan(&hkkaz);

        let mut segments = vec![
            Segment::Transactions {
                account: account.clone(),
                start_date,
                end_date,
                touchdown: touchdown.cloned(),
            },
        ];

        if is_first && needs_tan {
            info!("[FinTS] transactions: HKKAZ + HKTAN:4 (HIPINS: TAN required)");
            segments.push(Segment::TanProcess4 {
                reference_seg: SegmentRef::new("HKKAZ"),
                tan_medium: self.params.selected_tan_medium.clone(),
            });
        } else if is_first {
            info!("[FinTS] transactions: HKKAZ (HIPINS: PIN-only)");
        }

        let response = self.send_segments(&segments).await?;

        for c in response.all_codes() {
            if c.is_error() || c.is_warning() {
                info!("[FinTS] HKKAZ: {} - {}", c.code(), c.text);
            }
        }

        // TAN required but no exemption
        if response.needs_tan() && !response.has_sca_exemption() {
            if let Some(challenge) = response.get_tan_challenge() {
                return Ok(TransactionResult::NeedTan(challenge));
            }
        }

        // Check errors
        response.check_errors()?;

        // Extract MT940 data
        let mt940 = extract_mt940_data(&response.segments);
        let td = response.touchdown();

        Ok(TransactionResult::Success(TransactionPage {
            booked: Mt940Data(mt940.booked),
            pending: Mt940Data(mt940.pending),
            touchdown: td,
        }))
    }

    /// Request securities holdings (HKWPD).
    ///
    /// Takes a validated `Account` — IBAN and BIC are guaranteed non-empty.
    /// Automatically selects the correct HKWPD version from BPD.
    /// Pass `touchdown` from a previous `HoldingsPage` for pagination,
    /// or `None` for the first request.
    pub async fn holdings(
        &mut self,
        account: &Account,
        currency: Option<&Currency>,
        touchdown: Option<&TouchdownPoint>,
    ) -> Result<HoldingsResult> {
        let is_first = touchdown.is_none();
        let hkwpd = SegmentType::new("HKWPD");
        let needs_tan = self.params.needs_tan(&hkwpd);

        let mut segments = vec![
            Segment::Holdings {
                account: account.clone(),
                currency: currency.cloned(),
                touchdown: touchdown.cloned(),
            },
        ];

        if is_first && needs_tan {
            info!("[FinTS] holdings: HKWPD + HKTAN:4 (HIPINS: TAN required)");
            segments.push(Segment::TanProcess4 {
                reference_seg: SegmentRef::new("HKWPD"),
                tan_medium: self.params.selected_tan_medium.clone(),
            });
        } else if is_first {
            info!("[FinTS] holdings: HKWPD (HIPINS: PIN-only)");
        }

        let response = self.send_segments(&segments).await?;

        for c in response.all_codes() {
            if c.is_error() || c.is_warning() {
                info!("[FinTS] HKWPD: {} - {}", c.code(), c.text);
            }
        }

        // TAN required but no exemption
        if response.needs_tan() && !response.has_sca_exemption() {
            if let Some(challenge) = response.get_tan_challenge() {
                return Ok(HoldingsResult::NeedTan(challenge));
            }
        }

        // Check errors
        response.check_errors()?;

        // Parse HIWPD segments
        let holdings = parse_hiwpd(&response.segments);
        let td = response.touchdown();

        if holdings.is_empty() && td.is_none() {
            return Ok(HoldingsResult::Empty);
        }

        Ok(HoldingsResult::Success(HoldingsPage {
            holdings,
            touchdown: td,
        }))
    }

    /// End the dialog.
    pub async fn end(mut self) -> Result<()> {
        self.send_end().await
    }
}

// ── Dialog<TanPending> ──────────────────────────────────────────────────────

impl Dialog<TanPending> {
    /// Poll decoupled TAN status (HKTAN process S).
    /// Per spec: sends HKTAN alone, no business segments.
    /// Returns `Confirmed` (→ Open) or `Pending` (→ still TanPending).
    pub async fn poll(mut self, task_reference: &TaskReference) -> Result<PollResult> {
        let segments = [
            Segment::TanPollDecoupled {
                task_reference: task_reference.clone(),
                tan_medium: self.params.selected_tan_medium.clone(),
            },
        ];

        let response = self.send_segments(&segments).await?;

        for c in response.all_codes() {
            info!("[FinTS] Poll: {} - {}", c.code(), c.text);
        }

        // 3955/3956: still pending
        if response.is_decoupled_pending() {
            return Ok(PollResult::Pending(self));
        }

        // Check for errors (9xxx)
        response.check_errors()?;

        // 0020: confirmed → Open
        self.params.ingest_response(&response, &mut self.system_id);
        Ok(PollResult::Confirmed(self.transition(), response))
    }

    /// Submit TAN for process 2 (non-decoupled: chipTAN, SMS-TAN).
    /// TAN value is included in HNSHA.
    pub async fn submit_tan(mut self, task_reference: &TaskReference, tan: &str) -> Result<(Dialog<Open>, Response)> {
        let segments = [
            Segment::TanProcess2 {
                task_reference: task_reference.clone(),
                tan_medium: self.params.selected_tan_medium.clone(),
            },
        ];

        let response = self.send_segments_with_tan(&segments, tan).await?;
        response.check_errors()?;
        self.params.ingest_response(&response, &mut self.system_id);
        Ok((self.transition(), response))
    }

    /// Cancel: end dialog without completing TAN.
    pub async fn cancel(mut self) -> Result<()> {
        self.send_end().await
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Response parsing
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_response(data: &[u8], expected_msg_num: u16) -> Result<Response> {
    let outer_segments = parser::parse_message(data)?;

    if let Some(hnhbk) = outer_segments.iter().find(|s| s.segment_type() == "HNHBK") {
        let resp_num = hnhbk.deg(4).get_str(0);
        let expected = expected_msg_num.to_string();
        if resp_num != expected && !resp_num.is_empty() {
            warn!("Message number mismatch: expected {}, got {}", expected, resp_num);
        }
    }

    let mut all_segments = Vec::new();
    for seg in &outer_segments {
        if seg.segment_type() == "HNVSD" {
            if let Some(binary) = seg.deg(1).get(0).as_bytes() {
                match parser::parse_inner_segments(binary) {
                    Ok(inner) => all_segments.extend(inner),
                    Err(e) => warn!("Failed to parse HNVSD: {}", e),
                }
            }
        } else {
            all_segments.push(seg.clone());
        }
    }

    let mut global_codes = Vec::new();
    let mut segment_codes = Vec::new();
    for seg in &all_segments {
        match seg.segment_type() {
            "HIRMG" => global_codes.extend(ResponseCode::parse_from_segment(seg)),
            "HIRMS" => segment_codes.extend(ResponseCode::parse_from_segment(seg)),
            _ => {}
        }
    }

    Ok(Response { segments: all_segments, global_codes, segment_codes })
}
