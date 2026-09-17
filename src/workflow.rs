//! Bank workflow trait and DKB implementation.
//!
//! Each bank defines its own complete workflow via the `BankOps` trait.
//! The workflows compose typed Dialog transitions from `protocol.rs`.
//!
//! Compile-time safety: workflow methods take typed dialog states.
//! `fetch()` takes `Dialog<Open>` — you can't call it without authentication.

use tracing::{info, warn};

use crate::banks::BankConfig;
use crate::error::{FinTSError, Result};
use crate::protocol::*;
use crate::types::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Workflow result types
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of initiating a connection.
pub struct InitiateResult {
    pub dialog: Dialog<TanPending>,
    pub challenge: TanChallenge,
    pub tan_methods: Vec<TanMethod>,
    pub allowed_security_functions: Vec<SecurityFunction>,
    pub no_tan_required: bool,
    pub params: BankParams,
    pub system_id: SystemId,
}

/// Result when no TAN is required (SCA exemption).
pub struct InitiateNoTanResult {
    pub dialog: Dialog<Open>,
    pub params: BankParams,
    pub system_id: SystemId,
    pub tan_methods: Vec<TanMethod>,
    pub allowed_security_functions: Vec<SecurityFunction>,
}

/// Either we need TAN or we're already authenticated.
pub enum InitiateOutcome {
    NeedTan(InitiateResult),
    Authenticated(InitiateNoTanResult),
}

/// Result of fetching data from an open dialog.
pub struct FetchResult {
    pub balance: Option<AccountBalance>,
    pub transactions: Vec<Transaction>,
    pub holdings: Vec<SecurityHolding>,
}

/// Options controlling what data to fetch in a single authenticated dialog.
#[derive(Debug, Clone, Default)]
pub struct FetchOpts {
    /// Fetch balance (HKSAL). Default: true.
    pub balance: bool,
    /// Fetch transactions (HKKAZ). Default: true.
    pub transactions: bool,
    /// Fetch securities holdings (HKWPD). Default: true.
    pub holdings: bool,
    /// Days of transaction history to fetch. Default: 90.
    pub days: u32,
}

impl FetchOpts {
    /// Fetch everything: balance, transactions, and holdings.
    pub fn all(days: u32) -> Self {
        Self { balance: true, transactions: true, holdings: true, days }
    }
    /// Fetch only balance (single request, fast).
    pub fn balance_only() -> Self {
        Self { balance: true, transactions: false, holdings: false, days: 0 }
    }
    /// Skip holdings (for accounts without a depot).
    pub fn no_holdings(days: u32) -> Self {
        Self { balance: true, transactions: true, holdings: false, days }
    }
}

/// How the shared transaction fetch reacts when the bank demands an
/// additional TAN for the HKKAZ request.
enum TransactionTanPolicy {
    /// Abort the whole fetch with an error.
    Error,
    /// Stop paginating and return the transactions collected so far.
    Skip,
}

/// Shared balance fetch (HKSAL): best-effort, any failure yields `None`.
async fn fetch_balance(
    dialog: &mut Dialog<Open>,
    account: &Account,
    bank: &str,
) -> Option<AccountBalance> {
    match dialog.balance(account).await {
        Ok(BalanceResult::Success(b)) => {
            info!("[{}] Balance: {}", bank, b.amount);
            Some(b)
        }
        Ok(BalanceResult::NeedTan(_)) => {
            warn!("[{}] Balance requires additional TAN — skipping", bank);
            None
        }
        Ok(BalanceResult::Empty) => {
            warn!("[{}] No balance data in response", bank);
            None
        }
        Err(e) => {
            warn!("[{}] Balance failed: {}", bank, e);
            None
        }
    }
}

/// Shared transaction fetch (HKKAZ) with touchdown pagination and MT940 parsing.
async fn fetch_transactions(
    dialog: &mut Dialog<Open>,
    account: &Account,
    start_date: chrono::NaiveDate,
    end_date: chrono::NaiveDate,
    bank: &str,
    tan_policy: TransactionTanPolicy,
) -> Result<Vec<Transaction>> {
    info!("[{}] Transactions {} to {}", bank, start_date, end_date);

    let mut all_booked = Mt940Data::new();
    let mut all_pending = Mt940Data::new();
    let mut touchdown: Option<TouchdownPoint> = None;

    loop {
        let result = dialog.transactions(
            account, start_date, end_date, touchdown.as_ref(),
        ).await?;

        match result {
            TransactionResult::NeedTan(_) => match tan_policy {
                TransactionTanPolicy::Error => {
                    return Err(FinTSError::Dialog(
                        "Die Bank erfordert für Transaktionen eine weitere TAN-Freigabe.".into()
                    ));
                }
                TransactionTanPolicy::Skip => break,
            },
            TransactionResult::Success(page) => {
                if !page.booked.is_empty() { all_booked.extend(page.booked.0); }
                if !page.pending.is_empty() { all_pending.extend(page.pending.0); }
                touchdown = page.touchdown;
                if touchdown.is_none() { break; }
                info!("[{}] Touchdown: more data...", bank);
            }
        }
    }

    let mut transactions = parse_mt940(all_booked.as_bytes(), TransactionStatus::Booked)?;
    if !all_pending.is_empty() {
        transactions.extend(parse_mt940(all_pending.as_bytes(), TransactionStatus::Pending)?);
    }
    info!("[{}] {} transactions", bank, transactions.len());
    Ok(transactions)
}

// ═══════════════════════════════════════════════════════════════════════════════
// BankOps trait
// ═══════════════════════════════════════════════════════════════════════════════

/// Each bank implements its own workflow as typed Dialog transitions.
///
/// `fetch()` takes `&mut Dialog<Open>` and `&Account` — compile-time proof that:
/// 1. Authentication has been completed (Dialog<Open>)
/// 2. Account has valid IBAN + BIC (Account)
pub trait BankOps: Send + Sync {
    fn config(&self) -> &BankConfig;

    /// Phase 1: sync + init, return TAN challenge or authenticated dialog.
    fn initiate(
        &self,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        system_id: Option<&SystemId>,
        target_iban: Option<&Iban>,
        target_bic: Option<&Bic>,
    ) -> impl std::future::Future<Output = Result<InitiateOutcome>> + Send;

    /// Phase 2: fetch balance + transactions from an open dialog.
    /// Takes `&Account` — IBAN and BIC are guaranteed present.
    fn fetch(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
        days: u32,
    ) -> impl std::future::Future<Output = Result<FetchResult>> + Send;

    /// Fetch securities holdings from an open dialog.
    /// Takes `&Account` — IBAN and BIC are guaranteed present.
    /// Returns an empty Vec if the bank does not support depot queries.
    fn fetch_holdings(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
    ) -> impl std::future::Future<Output = Result<Vec<SecurityHolding>>> + Send;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DKB implementation
// ═══════════════════════════════════════════════════════════════════════════════

/// DKB (Deutsche Kreditbank) FinTS workflow.
///
/// DKB message flow per spec + empirical discovery:
/// ```text
///   Sync dialog:
///     Msg 1: HKIDN + HKVVB + HKSYN   → BPD, system_id
///     Msg 2: HKEND
///
///   Business dialog:
///     Msg 1: HKIDN + HKVVB + HKTAN:4(ref=HKIDN)  → InitResult
///       → TanRequired: push sent (3955)
///       → Opened: SCA exemption (3076)
///     Msg 2: HKTAN:S(task_ref)                     → PollResult
///       → Confirmed: 0020
///       → Pending: 3955/3956
///     Msg 3: HKSAL [+ HKTAN:4(ref=HKSAL)]         → SendResult
///       → Success: balance data (HISAL)
///       → NeedTan: additional TAN for balance
///     Msg 4: HKKAZ [+ HKTAN:4(ref=HKKAZ)]         → SendResult
///       → Success: transaction data (HIKAZ)
///       → Touchdown: more data, fetch again
///     Msg 5: HKEND
/// ```
pub struct Dkb {
    bank: BankConfig,
}

impl Dkb {
    pub fn new() -> Self {
        Self {
            bank: crate::banks::bank_by_blz("12030000")
                .expect("DKB (BLZ 12030000) must be in bank registry"),
        }
    }

    fn new_dialog(&self, username: &UserId, pin: &Pin, product_id: &ProductId) -> Result<Dialog<New>> {
        Dialog::new(
            self.bank.url.as_str(),
            &self.bank.blz,
            username,
            pin,
            product_id,
        )
    }
}

impl BankOps for Dkb {
    fn config(&self) -> &BankConfig { &self.bank }

    async fn initiate(
        &self,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        system_id: Option<&SystemId>,
        _target_iban: Option<&Iban>,
        _target_bic: Option<&Bic>,
    ) -> Result<InitiateOutcome> {
        // ── Phase 1: Sync dialog (get system_id + BPD) ──
        let mut sync_dialog = self.new_dialog(username, pin, product_id)?;
        if let Some(sid) = system_id {
            sync_dialog = sync_dialog.with_system_id(sid);
        }
        let (synced, _resp) = sync_dialog.sync().await?;
        let (sync_params, sys_id) = synced.end().await?;

        let sys_id = if sys_id.is_assigned() {
            sys_id
        } else {
            system_id.cloned().unwrap_or_else(SystemId::unassigned)
        };

        // ── Phase 2: Normal dialog init (triggers TAN or opens directly) ──
        let dialog = self.new_dialog(username, pin, product_id)?
            .with_system_id(&sys_id)
            .with_params(&sync_params);

        let init_result = dialog.init().await?;

        match init_result {
            InitResult::TanRequired(tan_pending, challenge, _resp) => {
                info!("[DKB] TAN required: decoupled={}, task_ref='{}'",
                    challenge.decoupled, challenge.task_reference);
                Ok(InitiateOutcome::NeedTan(InitiateResult {
                    params: tan_pending.bank_params().clone(),
                    system_id: tan_pending.system_id().clone(),
                    dialog: tan_pending,
                    challenge,
                    tan_methods: sync_params.tan_methods.clone(),
                    allowed_security_functions: sync_params.allowed_security_functions.clone(),
                    no_tan_required: false,
                }))
            }
            InitResult::Opened(open, _resp) => {
                info!("[DKB] Opened directly (SCA exemption)");
                Ok(InitiateOutcome::Authenticated(InitiateNoTanResult {
                    params: open.bank_params().clone(),
                    system_id: open.system_id().clone(),
                    dialog: open,
                    tan_methods: sync_params.tan_methods.clone(),
                    allowed_security_functions: sync_params.allowed_security_functions.clone(),
                }))
            }
        }
    }

    async fn fetch(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
        days: u32,
    ) -> Result<FetchResult> {
        // The generic workflow (balance + MT940 transactions + holdings) lives in
        // `GenericBank` — DKB reuses it rather than keeping its own copy.
        GenericBank::new(self.bank.clone()).fetch(dialog, account, days).await
    }

    async fn fetch_holdings(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
    ) -> Result<Vec<SecurityHolding>> {
        GenericBank::new(self.bank.clone()).fetch_holdings(dialog, account).await
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Bank registry
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// Generic bank — any FinTS endpoint (used for custom/unknown banks)
// ═══════════════════════════════════════════════════════════════════════════════

/// A generic FinTS bank implementation that works with any BankConfig.
/// Used when the bank ID is not in the registry (e.g. custom URL + BLZ).
pub struct GenericBank {
    bank: BankConfig,
}

impl GenericBank {
    pub fn new(config: BankConfig) -> Self {
        Self { bank: config }
    }

    fn new_dialog(&self, username: &UserId, pin: &Pin, product_id: &ProductId) -> Result<Dialog<New>> {
        Dialog::new(self.bank.url.as_str(), &self.bank.blz, username, pin, product_id)
    }
}

impl BankOps for GenericBank {
    fn config(&self) -> &BankConfig { &self.bank }

    async fn initiate(
        &self,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        system_id: Option<&SystemId>,
        _target_iban: Option<&Iban>,
        _target_bic: Option<&Bic>,
    ) -> Result<InitiateOutcome> {
        let mut sync_dialog = self.new_dialog(username, pin, product_id)?;
        if let Some(sid) = system_id {
            sync_dialog = sync_dialog.with_system_id(sid);
        }
        let (synced, _) = sync_dialog.sync().await?;
        let (sync_params, sys_id) = synced.end().await?;

        let sys_id = if sys_id.is_assigned() { sys_id }
            else { system_id.cloned().unwrap_or_else(SystemId::unassigned) };

        let dialog = self.new_dialog(username, pin, product_id)?
            .with_system_id(&sys_id)
            .with_params(&sync_params);

        let init_result = dialog.init().await?;

        match init_result {
            InitResult::TanRequired(tan_pending, challenge, _) => {
                let challenge = crate::protocol::TanChallenge {
                    decoupled: challenge.decoupled || tan_pending.bank_params().is_decoupled(),
                    ..challenge
                };
                Ok(InitiateOutcome::NeedTan(InitiateResult {
                    params: tan_pending.bank_params().clone(),
                    system_id: tan_pending.system_id().clone(),
                    dialog: tan_pending, challenge,
                    tan_methods: sync_params.tan_methods.clone(),
                    allowed_security_functions: sync_params.allowed_security_functions.clone(),
                    no_tan_required: false,
                }))
            }
            InitResult::Opened(open, _) => {
                Ok(InitiateOutcome::Authenticated(InitiateNoTanResult {
                    params: open.bank_params().clone(),
                    system_id: open.system_id().clone(),
                    dialog: open,
                    tan_methods: sync_params.tan_methods.clone(),
                    allowed_security_functions: sync_params.allowed_security_functions.clone(),
                }))
            }
        }
    }

    async fn fetch(&self, dialog: &mut Dialog<Open>, account: &Account, days: u32) -> Result<FetchResult> {
        let bank = self.bank.name.as_str();
        info!("[{}] Fetching IBAN={}, BIC={}", bank, account.iban(), account.bic());

        // ── Balance (HKSAL) ──
        let balance = fetch_balance(dialog, account, bank).await;

        // ── Transactions (HKKAZ) with pagination ──
        let end_date = chrono::Utc::now().date_naive();
        let start_date = end_date - chrono::Duration::days(days as i64);
        let transactions = fetch_transactions(
            dialog, account, start_date, end_date, bank, TransactionTanPolicy::Error,
        ).await?;

        // ── Holdings (HKWPD) — best-effort, non-fatal ──
        let holdings = match self.fetch_holdings(dialog, account).await {
            Ok(h) => {
                info!("[{}] {} holdings", bank, h.len());
                h
            }
            Err(e) => {
                warn!("[{}] Holdings fetch failed (non-fatal): {}", bank, e);
                Vec::new()
            }
        };

        Ok(FetchResult { balance, transactions, holdings })
    }

    async fn fetch_holdings(&self, dialog: &mut Dialog<Open>, account: &Account) -> Result<Vec<SecurityHolding>> {
        let bank = self.bank.name.as_str();

        let mut all_holdings = Vec::new();
        let mut touchdown: Option<TouchdownPoint> = None;

        loop {
            let result = dialog.holdings(
                account, None, touchdown.as_ref(),
            ).await?;

            match result {
                HoldingsResult::NeedTan(_) => {
                    warn!("[{}] Holdings requires additional TAN — skipping", bank);
                    return Ok(all_holdings);
                }
                HoldingsResult::Empty => {
                    info!("[{}] No holdings data (depot may be empty or not supported)", bank);
                    break;
                }
                HoldingsResult::Success(page) => {
                    info!("[{}] Got {} holdings", bank, page.holdings.len());
                    all_holdings.extend(page.holdings);
                    touchdown = page.touchdown;
                    if touchdown.is_none() { break; }
                    info!("[{}] Holdings touchdown: more data...", bank);
                }
            }
        }

        info!("[{}] Total: {} holdings", bank, all_holdings.len());
        Ok(all_holdings)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Bank registry
// ═══════════════════════════════════════════════════════════════════════════════

/// Enum dispatch for bank implementations — zero-cost, no dynamic dispatch.
///
/// New banks are added here as enum variants. This avoids `Box<dyn BankOps>`
/// which is incompatible with native async fn in traits.
pub enum AnyBank {
    Dkb(Dkb),
    Generic(GenericBank),
}

impl AnyBank {
    pub fn config(&self) -> &BankConfig {
        match self {
            AnyBank::Dkb(b) => b.config(),
            AnyBank::Generic(b) => b.config(),
        }
    }

    pub async fn initiate(
        &self,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        system_id: Option<&SystemId>,
        target_iban: Option<&Iban>,
        target_bic: Option<&Bic>,
    ) -> Result<InitiateOutcome> {
        match self {
            AnyBank::Dkb(b) => b.initiate(username, pin, product_id, system_id, target_iban, target_bic).await,
            AnyBank::Generic(b) => b.initiate(username, pin, product_id, system_id, target_iban, target_bic).await,
        }
    }

    pub async fn fetch(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
        days: u32,
    ) -> Result<FetchResult> {
        match self {
            AnyBank::Dkb(b) => b.fetch(dialog, account, days).await,
            AnyBank::Generic(b) => b.fetch(dialog, account, days).await,
        }
    }

    pub async fn fetch_holdings(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
    ) -> Result<Vec<SecurityHolding>> {
        match self {
            AnyBank::Dkb(b) => b.fetch_holdings(dialog, account).await,
            AnyBank::Generic(b) => b.fetch_holdings(dialog, account).await,
        }
    }

    /// Fetch data with fine-grained control via `FetchOpts`.
    /// This gives callers a single authenticated dialog for all operations.
    pub async fn fetch_with_opts(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
        opts: &FetchOpts,
    ) -> Result<FetchResult> {
        let bank = self.config().name.as_str();

        // ── Balance ──
        let balance = if opts.balance {
            fetch_balance(dialog, account, bank).await
        } else {
            None
        };

        // ── Transactions ──
        let transactions = if opts.transactions {
            let end_date = chrono::Utc::now().date_naive();
            let start_date = end_date - chrono::Duration::days(opts.days.max(1) as i64);
            fetch_transactions(
                dialog, account, start_date, end_date, bank, TransactionTanPolicy::Skip,
            ).await?
        } else {
            Vec::new()
        };

        // ── Holdings ──
        let holdings = if opts.holdings {
            match self.fetch_holdings(dialog, account).await {
                Ok(h) => h,
                Err(e) => { warn!("Holdings fetch failed: {}", e); Vec::new() }
            }
        } else {
            Vec::new()
        };

        Ok(FetchResult { balance, transactions, holdings })
    }
}

/// Look up a bank implementation by its BLZ (Bankleitzahl).
///
/// The BLZ is the canonical bank identifier — banks are dispatched based on it.
/// BLZ `12030000` → DKB implementation; all others → GenericBank.
pub fn bank_ops(blz: &str) -> Result<AnyBank> {
    let config = crate::banks::bank_by_blz(blz)
        .ok_or_else(|| FinTSError::Dialog(format!("Unknown BLZ: {}", blz)))?;
    match blz {
        "12030000" => Ok(AnyBank::Dkb(Dkb::new())),
        _ => Ok(AnyBank::Generic(GenericBank::new(config))),
    }
}

/// Create a bank implementation from a custom BankConfig (for non-registry banks).
pub fn bank_ops_with_config(config: BankConfig) -> AnyBank {
    AnyBank::Generic(GenericBank::new(config))
}

// ═══════════════════════════════════════════════════════════════════════════════
// MT940 parsing
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_mt940(data: &[u8], status: TransactionStatus) -> Result<Vec<Transaction>> {
    if data.is_empty() { return Ok(Vec::new()); }

    let (cow, _, had_errors) = encoding_rs::WINDOWS_1252.decode(data);
    if had_errors { warn!("MT940 encoding errors"); }
    let mt940_text = cow.into_owned();

    let cleaned: String = mt940_text.lines()
        .filter(|l| { let t = l.trim(); !t.is_empty() && t != "-" && t != "--" })
        .collect::<Vec<_>>().join("\r\n") + "\r\n";

    let sanitized = mt940::sanitizers::to_swift_charset(&cleaned);
    let messages = mt940::parse_mt940(&sanitized)
        .map_err(|e| FinTSError::Mt940(format!("MT940 parse error: {}", e)))?;

    let mut transactions = Vec::new();
    for msg in messages {
        for line in msg.statement_lines {
            let is_debit = matches!(line.ext_debit_credit_indicator, mt940::ExtDebitOrCredit::Debit);
            let amount = if is_debit { -line.amount } else { line.amount };

            let (applicant_name, applicant_iban, applicant_bic, purpose, posting_text) =
                match &line.information_to_account_owner {
                    Some(mt940::InformationToAccountOwner::Structured {
                        applicant_name, applicant_iban, applicant_bin, purpose, posting_text, ..
                    }) => (applicant_name.clone(), applicant_iban.clone(), applicant_bin.clone(), purpose.clone(), posting_text.clone()),
                    Some(mt940::InformationToAccountOwner::Plain(text)) => (None, None, None, Some(text.clone()), None),
                    None => (None, None, None, None, None),
                };

            let raw = serde_json::json!({
                "date": line.value_date.to_string(),
                "entry_date": line.entry_date.map(|d| d.to_string()),
                "amount": amount.to_string(),
                "currency": msg.opening_balance.iso_currency_code,
                "customer_ref": line.customer_ref,
                "bank_ref": line.bank_ref,
                "applicant_name": applicant_name,
                "applicant_iban": applicant_iban,
                "applicant_bic": applicant_bic,
                "purpose": purpose,
                "posting_text": posting_text,
            });

            transactions.push(Transaction {
                date: line.value_date, valuta_date: line.entry_date,
                amount,
                currency: Currency::new(&msg.opening_balance.iso_currency_code),
                applicant_name,
                applicant_iban: applicant_iban.map(|s| Iban::new(s)),
                applicant_bic: applicant_bic.map(|s| Bic::new(s)),
                purpose, posting_text,
                reference: Some(line.customer_ref.clone()),
                raw, status: status.clone(),
            });
        }
    }
    Ok(transactions)
}
