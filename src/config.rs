// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use std::collections::HashMap;

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
    /// Which site to connect to if not otherwise specified
    #[serde(default = "Config::default_site")]
    pub default_site: String,
    /// The sites that are registered to connect to
    #[serde(default = "Config::default_sites")]
    pub sites: HashMap<String, Site>,
    /// The default location of the identity to use
    #[serde(default = "Config::default_identity")]
    pub identity: Option<std::path::PathBuf>,
    /// Should Clifton check for version updates
    #[serde(default = "Config::default_check_version")]
    pub check_version: bool,
    /// Should the config be written out after successful auth
    #[serde(default = "Config::default_write_config")]
    pub write_config: bool,
    /// Should authentication be skipped if it's not needed
    #[serde(default = "Config::default_passive")]
    pub passive: bool,
}

impl Config {
    fn default_open_browser() -> bool {
        true
    }
    fn default_show_qr() -> bool {
        true
    }
    fn default_site() -> String {
        "brics".into()
    }
    fn default_sites() -> HashMap<String, Site> {
        [(
            "brics".to_string(),
            Site {
                #[allow(clippy::expect_used)]
                ca_url: "https://ca.isambard.ac.uk/"
                    .parse()
                    .expect("Default CA URL does not parse"),
            },
        )]
        .into()
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
    fn default_write_config() -> bool {
        false
    }
    fn default_passive() -> bool {
        false
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Site {
    /// The URL of the CA server
    pub ca_url: Url,
}
