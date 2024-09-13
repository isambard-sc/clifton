// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    /// Should the browser be automatically opened when authenticating
    #[serde(default = "Config::default_open_browser")]
    pub open_browser: bool,
    /// Should the QR code be shown when authenticating
    #[serde(default = "Config::default_show_qr")]
    pub show_qr: bool,
    /// The URL of the CA server
    #[serde(default = "Config::default_ca_url")]
    pub ca_url: Url,
    /// The OIDC client ID
    #[serde(default = "Config::default_client_id")]
    pub client_id: String,
    /// The default location of the identity to use
    #[serde(default = "Config::default_identity")]
    pub identity: Option<std::path::PathBuf>,
    /// Should Clifton check for version updates
    #[serde(default = "Config::default_check_version")]
    pub check_version: bool,
}

impl Config {
    fn default_open_browser() -> bool {
        true
    }
    fn default_show_qr() -> bool {
        true
    }
    fn default_ca_url() -> Url {
        #[allow(clippy::expect_used)]
        "https://ca.isambard.ac.uk/"
            .parse()
            .expect("Default CA URL does not parse")
    }
    fn default_client_id() -> String {
        "clifton".to_string()
    }
    fn default_identity() -> Option<std::path::PathBuf> {
        #[allow(clippy::expect_used)]
        ["id_ed25519", "id_ecdsa", "id_rsa"]
            .iter()
            .map(|t| {
                dirs::home_dir()
                    .expect("Cannot locate home directory.")
                    .join(".ssh")
                    .join(t)
            })
            .find(|i| i.try_exists().unwrap_or(false))
    }
    fn default_check_version() -> bool {
        true
    }
}
