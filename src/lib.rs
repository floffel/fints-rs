//! # fints — Native Rust FinTS 3.0 PinTan Client
//!
//! A pure Rust implementation of the FinTS 3.0 (formerly HBCI) banking protocol
//! for German online banking.
//!
//! ## Architecture
//!
//! 1. **Protocol layer** (`protocol`): Typestate `Dialog<S>` — the dialog's auth
//!    state is in the type system. Business ops on an unauthenticated dialog = compile error.
//!
//! 2. **Workflow layer** (`workflow`): Bank-specific workflows via `BankOps` trait.
//!
//! 3. **Bank modules** (`dkb`): High-level, bank-specific APIs.
//!
//! ## DKB — Quick start
//!
//! ```rust,no_run
//! use fints::{dkb, Account, UserId, Pin, ProductId};
//!
//! # async fn example() -> fints::Result<()> {
//! let (session, challenge) = dkb::connect(
//!     &UserId::new("user"), &Pin::new("pin"), &ProductId::new("PRODUCT_ID"), None,
//! ).await?;
//! // User confirms pushTAN in banking app...
//! let account = Account::new("DE89370400440532013000", "BYLADEM1001")?;  // German IBAN + BIC required!
//! let data = session.fetch(&account, 365).await?;
//! println!("Balance: {:?}, {} transactions", data.balance, data.transactions.len());
//! # Ok(())
//! # }
//! ```
//!
//! ## Generic bank access
//!
//! ```rust,no_run
//! use fints::{Flow, UserId, Pin, ProductId};
//!
//! # async fn example() -> fints::Result<()> {
//! let (mut flow, challenge) = Flow::initiate(
//!     "12030000", &UserId::new("user"), &Pin::new("pin"), &ProductId::new("PRODUCT_ID"),
//!     None, None, None,
//! ).await?;
//! let result = flow.confirm_and_fetch("DE123...", "BYLADEM...", 365).await?;
//! # Ok(())
//! # }
//! ```

// ── Infrastructure ──
pub mod banks;
pub mod banks_generated;
pub mod error;
pub(crate) mod message;
pub(crate) mod parser;
pub(crate) mod segments;
pub(crate) mod serializer;
pub(crate) mod transport;
pub mod types;

// ── Tooling ──
pub mod debug;
pub mod audit;

// ── Architecture ──
pub mod protocol;
pub mod workflow;
pub mod flow;

// ── Bank APIs ──
pub mod dkb;

// ═══════════════════════════════════════════════════════════════════════════════
// Re-exports
// ═══════════════════════════════════════════════════════════════════════════════

// Flow layer
pub use flow::{Flow, ChallengeInfo, SyncResult, FetchOptions};

// Workflow layer
pub use workflow::{BankOps, AnyBank, Dkb, GenericBank, bank_ops, bank_ops_with_config};
pub use workflow::{InitiateOutcome, InitiateResult, InitiateNoTanResult, FetchResult, FetchOpts};

// Protocol layer
pub use protocol::{
    Dialog, Response, TanChallenge, BankParams, Account,
    New, Synced, Open, TanPending,
    InitResult, SendResult, PollResult,
    BalanceResult, TransactionResult, TransactionPage,
    HoldingsResult, HoldingsPage,
};

// Domain types
pub use types::{
    AccountBalance, SepaAccount, Transaction, TransactionStatus, TanMethod,
    SecurityHolding, Isin, Wkn,
    Blz, UserId, Pin, SystemId, ProductId, DialogId, SecurityFunction,
    TaskReference, SegmentType, TanMediumName, TouchdownPoint, SegmentRef,
    Currency, Iban, Bic, TanProcess, ResponseCodeKind, ResponseCode,
    BankName, FinTSUrl, ChallengeText, HhdUcData, Mt940Data,
};
pub use error::{FinTSError, Result};
pub use banks::{BankConfig, all_banks, bank_by_blz};

// Debug / audit tooling
pub use debug::{DecodedMessage, DecodedSegment, VerbosityLevel, decode_message, format_decoded};
pub use audit::{AuditReport, Violation, ViolationSeverity, audit_client_message, audit_server_response};
