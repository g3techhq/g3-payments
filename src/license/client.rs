//! Activation, re-check and deactivation against `g3-payments-server`.
//!
//! Every route is under `{base}/api/v1/apps/{app}/licenses/`, and takes and
//! answers JSON (the [`wire`] types, shared with the server):
//!
//! | Route | Answer |
//! | --- | --- |
//! | `POST activate` `{key, machine, machine_name}` | 200 `{license}`, or an error code |
//! | `POST check` `{key, machine}` | 200 `{status: "active" \| "revoked"}` |
//! | `POST deactivate` `{key, machine}` | 200 `{}` |
//!
//! The buy page is `{base}/apps/{app}/buy`; Checkout returns the buyer to a
//! page that shows the key.

use super::file::normalize_key;

/// The JSON the license routes take and answer.
pub mod wire {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ActivateRequest {
        pub key: String,
        pub machine: String,
        /// A name the buyer recognises, such as the computer's host name,
        /// shown when they manage their activations.
        #[serde(default)]
        pub machine_name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ActivateResponse {
        pub license: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MachineRequest {
        pub key: String,
        pub machine: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CheckResponse {
        /// `active` or `revoked`.
        pub status: String,
    }

    /// An error answer. `limit` comes with `machine_limit`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ErrorResponse {
        pub error: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<u32>,
    }

    pub const UNKNOWN_KEY: &str = "unknown_key";
    pub const NOT_PAID: &str = "not_paid";
    pub const REVOKED: &str = "revoked";
    pub const MACHINE_LIMIT: &str = "machine_limit";
    pub const BAD_REQUEST: &str = "bad_request";
}

/// Why activation failed, worded for the person entering the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivateError {
    /// No such key for this app.
    UnknownKey,
    /// The key exists but its payment has not gone through yet.
    NotPaid,
    /// The purchase was refunded.
    Revoked,
    /// The key is active on as many machines as it allows.
    MachineLimit(u32),
    /// The server answered with a license this app cannot read.
    BadLicense,
    /// The server could not be reached or failed. Worth trying again.
    Unavailable(String),
}

impl std::fmt::Display for ActivateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownKey => f.write_str("That license key isn't one we know. Check it and try again."),
            Self::NotPaid => f.write_str("That purchase hasn't gone through yet. Try again in a minute."),
            Self::Revoked => f.write_str("That license was refunded and no longer works."),
            Self::MachineLimit(limit) => write!(
                f,
                "That key is already in use on {limit} computers. Deactivate one of them first."
            ),
            Self::BadLicense => f.write_str("The license server sent something this version can't read. Update the app and try again."),
            Self::Unavailable(_) => f.write_str("Couldn't reach the license server. Check your connection and try again."),
        }
    }
}

impl std::error::Error for ActivateError {}

/// A re-check's answer. Only `Revoked` locks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    Active,
    Revoked,
    /// No answer, or one this version cannot read. Changes nothing.
    Unreachable,
}

/// Talks to the license server for one app.
#[derive(Clone, Debug)]
pub struct LicenseClient {
    base: String,
    app: String,
}

impl LicenseClient {
    /// `base` is the server's origin, such as `https://pay.g3tech.net`;
    /// `app` this app's id there.
    pub fn new(base: impl Into<String>, app: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            app: app.into(),
        }
    }

    pub fn app(&self) -> &str {
        &self.app
    }

    /// The page to send a buyer to, in their browser.
    pub fn buy_url(&self) -> String {
        format!("{}/apps/{}/buy", self.base, self.app)
    }

    fn route(&self, name: &str) -> String {
        format!("{}/api/v1/apps/{}/licenses/{name}", self.base, self.app)
    }

    /// Activates `key` on `machine`, returning the signed license file.
    pub async fn activate(
        &self,
        key: &str,
        machine: &str,
        machine_name: &str,
    ) -> Result<String, ActivateError> {
        let request = wire::ActivateRequest {
            key: normalize_key(key),
            machine: machine.into(),
            machine_name: machine_name.into(),
        };
        let response = http()?
            .post(self.route("activate"))
            .json(&request)
            .send()
            .await
            .map_err(|error| ActivateError::Unavailable(error.without_url().to_string()))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| ActivateError::Unavailable(error.without_url().to_string()))?;
        if status.is_success() {
            return serde_json::from_slice::<wire::ActivateResponse>(&body)
                .map(|answer| answer.license)
                .map_err(|_| ActivateError::BadLicense);
        }
        Err(match serde_json::from_slice::<wire::ErrorResponse>(&body) {
            Ok(answer) => match answer.error.as_str() {
                wire::UNKNOWN_KEY => ActivateError::UnknownKey,
                wire::NOT_PAID => ActivateError::NotPaid,
                wire::REVOKED => ActivateError::Revoked,
                wire::MACHINE_LIMIT => ActivateError::MachineLimit(answer.limit.unwrap_or(0)),
                other => ActivateError::Unavailable(other.to_string()),
            },
            Err(_) => ActivateError::Unavailable(format!("license server answered {status}")),
        })
    }

    /// Asks whether the license on `machine` still stands.
    pub async fn check(&self, key: &str, machine: &str) -> CheckOutcome {
        let request = wire::MachineRequest {
            key: normalize_key(key),
            machine: machine.into(),
        };
        let Ok(client) = http() else {
            return CheckOutcome::Unreachable;
        };
        let Ok(response) = client.post(self.route("check")).json(&request).send().await else {
            return CheckOutcome::Unreachable;
        };
        if !response.status().is_success() {
            return CheckOutcome::Unreachable;
        }
        match response.json::<wire::CheckResponse>().await {
            Ok(answer) if answer.status == "active" => CheckOutcome::Active,
            Ok(answer) if answer.status == "revoked" => CheckOutcome::Revoked,
            _ => CheckOutcome::Unreachable,
        }
    }

    /// Frees this machine's activation, so the key can move to another.
    pub async fn deactivate(&self, key: &str, machine: &str) -> Result<(), ActivateError> {
        let request = wire::MachineRequest {
            key: normalize_key(key),
            machine: machine.into(),
        };
        let response = http()?
            .post(self.route("deactivate"))
            .json(&request)
            .send()
            .await
            .map_err(|error| ActivateError::Unavailable(error.without_url().to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ActivateError::Unavailable(format!(
                "license server answered {}",
                response.status()
            )))
        }
    }
}

fn http() -> Result<reqwest::Client, ActivateError> {
    #[cfg(not(target_arch = "wasm32"))]
    let _ = rustls::crypto::ring::default_provider().install_default();
    let builder = reqwest::Client::builder();
    #[cfg(not(target_arch = "wasm32"))]
    let builder = builder.timeout(std::time::Duration::from_secs(15));
    builder
        .build()
        .map_err(|error| ActivateError::Unavailable(error.without_url().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_and_the_buy_page_sit_under_the_app() {
        let client = LicenseClient::new("https://pay.example.com/", "tally");
        assert_eq!(client.buy_url(), "https://pay.example.com/apps/tally/buy");
        assert_eq!(
            client.route("activate"),
            "https://pay.example.com/api/v1/apps/tally/licenses/activate"
        );
    }

    #[tokio::test]
    async fn an_unreachable_server_never_reads_as_revoked() {
        let client = LicenseClient::new("http://127.0.0.1:9", "tally");
        assert_eq!(
            client.check("TALLY-AAAA", "m1").await,
            CheckOutcome::Unreachable
        );
        assert!(matches!(
            client.activate("TALLY-AAAA", "m1", "pc").await,
            Err(ActivateError::Unavailable(_))
        ));
    }
}
