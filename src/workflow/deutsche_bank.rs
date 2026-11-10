use tracing::debug;

use crate::BankConfig;
use crate::error::Result;
use crate::protocol::*;
use crate::types::*;

use super::{BankOps, FetchResult, GenericBank, InitiateNoTanResult, InitiateOutcome, InitiateResult};

pub struct DeutscheBank {
    bank: BankConfig,
}

impl DeutscheBank {
    pub fn new(config: BankConfig) -> Self {
        Self { bank: config }
    }
}

impl BankOps for DeutscheBank {
    fn config(&self) -> &BankConfig {
        &self.bank
    }

    async fn initiate(
        &self,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        system_id: Option<&SystemId>,
        _target_iban: Option<&Iban>,
        _target_bic: Option<&Bic>,
    ) -> Result<InitiateOutcome> {
        debug!("INIT DEUTSCHE BANK");
        let mut sync = self.new_dialog(username, pin, product_id)?;
        if let Some(sid) = system_id {
            sync = sync.with_system_id(sid);
        }
        let (synced, _) = sync.sync().await?;
        let (mut params, sys_id) = synced.end().await?;

        let sys_id = if sys_id.is_assigned() {
            sys_id
        } else {
            system_id.cloned().unwrap_or_else(SystemId::unassigned)
        };

        // Deutsche Bank requires selecting an explicit TAN medium
        if params.selected_tan_medium.is_none() {
            let tab_dialog = self
                .new_dialog(username, pin, product_id)?
                .with_system_id(&sys_id)
                .with_params(&params);

            if let Ok(media) = tab_dialog.query_tan_media().await {
                if let Some(first) = media.first() {
                    params.selected_tan_medium = Some(TanMediumName::new(first));
                }
            }
        }

        let dialog = self
            .new_dialog(username, pin, product_id)?
            .with_system_id(&sys_id)
            .with_params(&params);

        match dialog.init().await? {
            InitResult::TanRequired(tan_pending, challenge, _) => {
                let challenge = TanChallenge {
                    decoupled: challenge.decoupled || tan_pending.bank_params().is_decoupled(),
                    ..challenge
                };
                Ok(InitiateOutcome::NeedTan(InitiateResult {
                    params: tan_pending.bank_params().clone(),
                    system_id: tan_pending.system_id().clone(),
                    dialog: tan_pending,
                    challenge,
                    tan_methods: params.tan_methods.clone(),
                    allowed_security_functions: params.allowed_security_functions.clone(),
                    no_tan_required: false,
                }))
            }
            InitResult::Opened(open, _) => {
                Ok(InitiateOutcome::Authenticated(InitiateNoTanResult {
                    params: open.bank_params().clone(),
                    system_id: open.system_id().clone(),
                    dialog: open,
                    tan_methods: params.tan_methods.clone(),
                    allowed_security_functions: params.allowed_security_functions.clone(),
                }))
            }
        }
    }

    async fn fetch(&self, dialog: &mut Dialog<Open>, account: &Account, days: u32) -> Result<FetchResult> {
        GenericBank::new(self.bank.clone()).fetch(dialog, account, days).await
    }

    async fn fetch_holdings(&self, dialog: &mut Dialog<Open>, account: &Account) -> Result<Vec<SecurityHolding>> {
        GenericBank::new(self.bank.clone()).fetch_holdings(dialog, account).await
    }
}
