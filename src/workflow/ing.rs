use tracing::debug;

use crate::BankConfig;
use crate::error::Result;
use crate::protocol::*;
use crate::types::*;

use super::BankOps;
use super::FetchResult;
use super::InitiateNoTanResult;
use super::InitiateOutcome;

pub struct Ing {
    bank: BankConfig,
}

impl Ing {
    pub fn new(config: BankConfig) -> Self {
        Self { bank: config }
    }
}

impl BankOps for Ing {
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
        debug!("INIT ING");
        let sys_id = system_id
            .filter(|s| s.is_assigned())
            .cloned()
            .unwrap_or_else(|| SystemId::new(format!("{:016X}", rand::random::<u64>())));

        let dialog = Dialog::new(
            self.bank.url.as_str(),
            &self.bank.blz,
            username,
            pin,
            product_id,
        )?
        .with_system_id(&sys_id)
        .with_security_function(SecurityFunction::new("900"));

        let (open_dialog, _) = dialog.init_no_tan().await?;
        Ok(InitiateOutcome::Authenticated(InitiateNoTanResult {
            tan_methods: open_dialog.bank_params().tan_methods.clone(),
            allowed_security_functions: open_dialog.bank_params().allowed_security_functions.clone(),
            system_id: open_dialog.system_id().clone(),
            params: open_dialog.bank_params().clone(),
            dialog: open_dialog,
        }))
    }

    async fn fetch(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
        days: u32,
    ) -> Result<FetchResult> {
        super::Dkb::new().fetch(dialog, account, days).await
    }

    async fn fetch_holdings(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
    ) -> Result<Vec<SecurityHolding>> {
        super::Dkb::new().fetch_holdings(dialog, account).await
    }
}
