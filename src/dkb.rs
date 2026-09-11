//! DKB (Deutsche Kreditbank) high-level API.
//!
//! Provides a clean, bank-specific entry point for DKB FinTS operations.
//! All methods use the typestate Dialog under the hood — you cannot misuse them.
//!
//! ## Interactive two-step flow
//!
//! ```rust,no_run
//! use fints::{dkb, Account, UserId, Pin, ProductId};
//!
//! # async fn example() -> fints::Result<()> {
//! // Step 1: Connect and get TAN challenge
//! let (session, challenge) = dkb::connect(
//!     &UserId::new("username"), &Pin::new("pin"), &ProductId::new("PRODUCT_ID"), None,
//! ).await?;
//! println!("Please confirm in your banking app: {}", challenge.challenge);
//!
//! // Step 2: Create a validated account (BIC required — compile-time safety)
//! let account = Account::new("DE89370400440532013000", "BYLADEM1001")?;
//!
//! // Step 3: After user confirms, fetch data
//! let result = session.fetch(&account, 365).await?;
//! println!("Balance: {:?}", result.balance);
//! println!("{} transactions", result.transactions.len());
//! # Ok(())
//! # }
//! ```

use crate::error::{FinTSError, Result};
use crate::protocol::*;
use crate::types::{SystemId, TaskReference, ChallengeText, HhdUcData, UserId, Pin, ProductId};
use crate::workflow::{BankOps, Dkb, FetchResult, InitiateOutcome};

/// A DKB session in progress. Wraps the dialog state machine.
pub enum Session {
    /// Waiting for TAN confirmation (pushTAN).
    WaitingForTan {
        dialog: Dialog<TanPending>,
        task_reference: TaskReference,
        bank: Dkb,
        system_id: SystemId,
    },
    /// Already authenticated (SCA exemption).
    Ready {
        dialog: Dialog<Open>,
        bank: Dkb,
        system_id: SystemId,
    },
}

/// Challenge information returned from `connect()`.
pub struct Challenge {
    /// Text to display to the user.
    pub challenge: ChallengeText,
    /// HHD-UC data for optical TAN methods (None for pushTAN).
    pub challenge_hhduc: Option<HhdUcData>,
    /// Whether this is a decoupled method (pushTAN = true).
    pub decoupled: bool,
    /// If true, no TAN needed — call `fetch()` immediately.
    pub no_tan_required: bool,
}

/// Result of a successful fetch operation.
pub use crate::workflow::FetchResult as SyncData;

/// Connect to DKB and get a TAN challenge.
///
/// This performs:
/// 1. Sync dialog (get system_id + BPD)
/// 2. Normal dialog init with HKTAN:4 (triggers pushTAN)
///
/// Returns a `Session` (holding the dialog in the correct typestate)
/// and a `Challenge` with info for the user.
pub async fn connect(
    username: &UserId,
    pin: &Pin,
    product_id: &ProductId,
    system_id: Option<&SystemId>,
) -> Result<(Session, Challenge)> {
    let bank = Dkb::new();

    let outcome = bank.initiate(username, pin, product_id, system_id, None, None).await?;

    match outcome {
        InitiateOutcome::NeedTan(result) => {
            let challenge = Challenge {
                challenge: result.challenge.challenge.clone(),
                challenge_hhduc: result.challenge.challenge_hhduc.clone(),
                decoupled: result.challenge.decoupled,
                no_tan_required: false,
            };
            let session = Session::WaitingForTan {
                dialog: result.dialog,
                task_reference: result.challenge.task_reference,
                bank,
                system_id: result.system_id,
            };
            Ok((session, challenge))
        }
        InitiateOutcome::Authenticated(result) => {
            let challenge = Challenge {
                challenge: ChallengeText::new(""),
                challenge_hhduc: None,
                decoupled: false,
                no_tan_required: true,
            };
            let session = Session::Ready {
                dialog: result.dialog,
                bank,
                system_id: result.system_id,
            };
            Ok((session, challenge))
        }
    }
}

impl Session {
    /// Fetch balance and transactions for an account.
    ///
    /// Takes `&Account` — IBAN and BIC are guaranteed present at compile time.
    /// If TAN is pending (pushTAN), this polls the bank first.
    /// Returns `Err` with "TAN still pending" if not yet confirmed — retry after waiting.
    ///
    /// On success, the dialog is closed and the session is consumed.
    pub async fn fetch(
        self,
        account: &Account,
        days: u32,
    ) -> Result<FetchResult> {
        match self {
            Session::WaitingForTan { dialog, task_reference, bank, .. } => {
                let poll_result = dialog.poll(&task_reference).await?;
                match poll_result {
                    PollResult::Confirmed(mut open, _response) => {
                        let result = bank.fetch(&mut open, account, days).await?;
                        open.end().await.ok();
                        Ok(result)
                    }
                    PollResult::Pending(_dialog) => {
                        Err(FinTSError::Dialog(
                            "TAN still pending: user has not yet confirmed in banking app".into()
                        ))
                    }
                }
            }
            Session::Ready { mut dialog, bank, .. } => {
                let result = bank.fetch(&mut dialog, account, days).await?;
                dialog.end().await.ok();
                Ok(result)
            }
        }
    }

    /// Get the system ID (persist this for future sessions to avoid re-sync).
    pub fn system_id(&self) -> &SystemId {
        match self {
            Session::WaitingForTan { system_id, .. } => system_id,
            Session::Ready { system_id, .. } => system_id,
        }
    }
}
