// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    /// The URL of the KeyCloak instance
    #[serde(default = "Config::default_keycloak_url")]
    pub keycloak_url: Url,
    /// The URL of the Waldur API server
    #[serde(default = "Config::default_waldur_api_url")]
    pub waldur_api_url: Url,
    /// The client ID in KeyCloak
    #[serde(default = "Config::default_client_id")]
    pub client_id: String,
    /// The default location of the identity to use
    #[serde(default = "Config::default_identity")]
    pub identity: std::path::PathBuf,
}

impl Config {
    fn default_keycloak_url() -> Url {
        #[allow(clippy::expect_used)]
        "https://keycloak.isambard.ac.uk/realms/isambard/"
            .parse()
            .expect("Default KeyCloak path does not parse")
    }
    fn default_waldur_api_url() -> Url {
        #[allow(clippy::expect_used)]
        "https://portal-api.isambard.ac.uk/"
            .parse()
            .expect("Default Waldur API path does not parse")
    }
    fn default_client_id() -> String {
        "clifton".to_string()
    }
    fn default_identity() -> std::path::PathBuf {
        #[allow(clippy::expect_used)]
        // TODO Check for existence of different keys and fall back.
        dirs::home_dir()
            .expect("Cannot locate home directory")
            .join(".ssh")
            .join("id_ed25519")
    }
}
