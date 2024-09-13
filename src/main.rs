// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use clap::{CommandFactory as _, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::IsTerminal};

use crate::auth::get_keycloak_token;

pub mod auth;
pub mod cache;
pub mod config;
mod version;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

fn version() -> &'static str {
    built_info::GIT_VERSION.unwrap_or(built_info::PKG_VERSION)
}

#[derive(Deserialize)]
struct CertificateSignResponse {
    certificate: ssh_key::Certificate,
    platforms: Platforms,
    projects: Projects,
    short_name: String,
    user: String,
    #[serde(
        deserialize_with = "CertificateSignResponse::check_version",
        rename = "version"
    )]
    _version: u32,
}

impl CertificateSignResponse {
    /// The version of the response that the portal should return.
    const VERSION: u32 = 2;
    fn check_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u32::deserialize(deserializer)?;
        let expected = Self::VERSION;
        if v != expected {
            return Err(serde::de::Error::custom(format!(
                "mismatched version `{v}` for certificate response, expected `{expected}`"
            )));
        }
        Ok(v)
    }
}

type Projects = HashMap<String, Vec<String>>;

type Platforms = HashMap<String, Platform>;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Platform {
    alias: String,
    #[serde(with = "http_serde::authority")]
    hostname: http::uri::Authority,
    #[serde(with = "http_serde::option::authority")]
    proxy_jump: Option<http::uri::Authority>,
}

#[derive(Deserialize, Serialize)]
struct CertificateConfigCache {
    platforms: Platforms,
    projects: Projects,
    user: String,
    short_name: String,
    identity: std::path::PathBuf,
}

impl CertificateConfigCache {
    fn from_reponse(r: CertificateSignResponse, identity: std::path::PathBuf) -> Self {
        CertificateConfigCache {
            platforms: r.platforms,
            projects: r.projects,
            short_name: r.short_name,
            user: r.user,
            identity,
        }
    }
}

#[derive(Parser)]
#[command(version = version(), about, long_about = None)]
/// Connect to Isambard
struct Args {
    #[arg(
        long,
        help=format!(
            "The clifton config file to use [default: {}]",
            &default_config_path().display(),
        )
    )]
    config_file: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate and retrieve signed SSH certificate
    Auth {
        /// The SSH identity (private key) to use. Should be a path like ~/.ssh/id_ed25519
        #[arg(short = 'i', long)]
        identity: Option<std::path::PathBuf>,
        /// Should the browser be opened automatically
        #[arg(long)] // See https://github.com/clap-rs/clap/issues/815 for tracking issue
        open_browser: Option<bool>,
        /// Should the QR code be shown on the screen
        #[arg(long)]
        show_qr: Option<bool>,
    },
    /// Display the OpenSSH config
    SshConfig {
        /// Generate the SSH config snippet
        #[command(subcommand)]
        command: Option<SshConfigCommands>,
    },
    /// Display the SSH command line to use for each project.
    /// Note that the given command may not work for non-standard identity file locations.
    SshCommand {
        /// The short name of the project to provide the command for
        project: String,
        /// The platform to access the project on
        platform: Option<String>,
    },
    /// Empty the cache
    #[command(hide = true)]
    ClearCache,
}

#[derive(Subcommand)]
enum SshConfigCommands {
    /// Write the config to an SSH config file which is included in the main one
    Write {
        /// The main SSH config file to write to
        #[arg(
            long,
            default_value_os_t = dirs::home_dir()
                .expect("Could not find home directory.")
                .join(".ssh")
                .join("config")
        )]
        ssh_config: std::path::PathBuf,
    },
}

fn default_config_path() -> std::path::PathBuf {
    dirs::config_local_dir()
        .unwrap_or(
            ".".parse()
                .expect("Could not parse fallback config directory."),
        )
        .join("clifton")
        .join("config.toml")
}

fn main() -> Result<()> {
    // Read the command line arguments
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(err) => {
            err.print().context("Failed to write Clap error.")?;
            std::process::exit(64); // sysexit EX_USAGE
        }
    };

    // Load settings from the config file
    let config_file_path = match &args.config_file {
        Some(f) => match f.try_exists() {
            Ok(true) => shellexpand::path::tilde(f),
            Ok(false) => anyhow::bail!(format!("Config file `{}` not found.", &f.display())),
            Err(err) => return Err(err).context("Could not determine if config file exists."),
        },
        None => default_config_path().into(),
    };

    let config: config::Config = match std::fs::read_to_string(config_file_path) {
        Ok(config_string) => toml::from_str(&config_string)?,
        Err(_) => toml::from_str("")?,
    };

    if config.check_version {
        let grace_days = 2;
        if let Err(e) = version::check_for_new_version(
            "https://isambard-sc.github.io/clifton/releases".parse()?,
            grace_days,
        )
        .context("Failed to check for new version of Clifton.")
        {
            eprintln!("{:}", &e);
        }
    }

    let cert_details_file_name = "cert.json";

    match &args.command {
        Some(Commands::Auth {
            identity,
            open_browser,
            show_qr,
        }) => {
            let open_browser = open_browser.unwrap_or(config.open_browser);
            let show_qr = show_qr.unwrap_or(config.show_qr);

            // Load the user's public key
            let identity_file = shellexpand::path::tilde(
                identity
                    .as_ref()
                    .or(config.identity.as_ref())
                    .context("No identity file specified.")?,
            );
            if !identity_file.is_file() {
                anyhow::bail!(format!(
                    "Identity file {} not found.\nEither specify the identity file (see `clifton auth --help`) or create a new key.",
                    &identity_file.display(),
                ))
            }
            let identity = match ssh_key::PrivateKey::read_openssh_file(&identity_file) {
                Ok(i) => i,
                Err(e) => {
                    match e {
                        ssh_key::Error::Encoding(_) | ssh_key::Error::FormatEncoding => {
                            if identity_file.extension().is_some_and(|e| e == "pub") {
                                anyhow::bail!(anyhow::anyhow!(e).context("Could not decode the private key. Most likely this is caused by you passing your *public* key instead of your *private* key."))
                            } else {
                                anyhow::bail!(anyhow::anyhow!(e).context("Could not decode the private key. Most likely this is caused by you trying to read an RSA key stored in an old format. Try generating a new key."))
                            }
                        }
                        _ => anyhow::bail!(
                            anyhow::anyhow!(e).context("Could not read SSH identity file.")
                        ),
                    };
                }
            };

            if !identity.is_encrypted() {
                eprintln!(
                    "Warning, the SSH identity file `{}` is unencrypted.",
                    identity_file.display()
                );
            }

            let issuer: url::Url = reqwest::blocking::get(format!("{}issuer", &config.ca_url))
                .context("Could not parse CA issuer URL.")?
                .error_for_status()
                .context("Could not get CA issuer URL")?
                .text()
                .context("Could not parse CA issuer URL reponse as text.")?
                .parse()
                .context("Could not parse CA issuer URL as URL.")?;

            let cert_file_path = identity_file.with_file_name(
                [
                    identity_file
                        .file_name()
                        .context("Could not understand identity file name.")?,
                    std::ffi::OsStr::new("-cert.pub"),
                ]
                .join(std::ffi::OsStr::new("")),
            );
            let token_cache_path = "token";
            // Try to load the Waldur API key from the cache
            println!(
                "Retrieving certificate for identity `{}`.",
                &identity_file.display()
            );
            let cert = cache::read_file(token_cache_path)
                .ok()
                .and_then(|token| {
                    // If it's there, try to use it
                    get_cert(&identity, &config.ca_url, &token).ok()
                })
                .map_or_else(
                    || {
                        // If the certificate could not be fetched, renew the API token
                        let token = get_keycloak_token(
                            &config.client_id,
                            &issuer,
                            open_browser,
                            show_qr,
                            token_cache_path,
                        )?;
                        get_cert(&identity, &config.ca_url, token.secret())
                    },
                    Ok,
                )
                .context("Could not get certificate.");
            let cert = match cert {
                Ok(cert) => cert,
                Err(e) => {
                    cache::delete_file(cert_details_file_name).unwrap_or_default();
                    anyhow::bail!(e)
                }
            };
            std::fs::write(
                &cert_file_path,
                format!(
                    "{}\n",
                    &cert
                        .certificate
                        .to_openssh()
                        .context("Could not convert certificate to OpenSSH format.")?
                ),
            )
            .context("Could not write certificate file.")?;
            let green = anstyle::Style::new()
                .fg_color(Some(anstyle::AnsiColor::Green.into()))
                .bold();
            match cert.projects.len() {
                0 => {
                    anyhow::bail!("Did not authenticate with any projects.")
                }
                _ => {
                    let projects = cert
                        .projects
                        .keys()
                        .map(|p| format!(" - {}", &p))
                        .collect::<Vec<_>>()
                        .join("\n");
                    println!(
                        "{green}Successfully authenticated as {} ({}) and downloaded SSH certificate for projects{green:#}:\n{projects}\n",
                        &cert.user, &cert.short_name
                    );
                }
            }
            type Tz = chrono::offset::Utc; // TODO This is UNIX time, not UTC
            let valid_before: chrono::DateTime<Tz> = cert.certificate.valid_before_time().into();
            let valid_for = valid_before - Tz::now();
            cache::write_file(
                cert_details_file_name,
                serde_json::to_string(&CertificateConfigCache::from_reponse(
                    cert,
                    identity_file.to_path_buf(),
                ))?,
            )
            .context("Could not write certificate details cache.")?;
            println!(
                "Certificate valid for {} hours and {} minutes.",
                valid_for.num_hours(),
                valid_for.num_minutes() % 60,
            );
            println!("Certificate file written to {}", &cert_file_path.display());
            println!(
                "You may now want to run `clifton ssh-config write` to configure your SSH config aliases."
            );
        }
        Some(Commands::SshConfig { command }) => {
            let f: CertificateConfigCache = serde_json::from_str(
                &cache::read_file(cert_details_file_name).context(
                    "Could not read certificate details cache. Have you run `clifton auth`?",
                )?,
            )
            .context("Could not parse certificate details cache. Try rerunning `clifton auth`.")?;
            let jump_configs = f
                .platforms
                .values()
                .map(|c| {
                    if let Some(proxy_jump) = &c.proxy_jump {
                        let jump_alias = format!("jump.{}", &c.alias);
                        let jump_config = format!(
                            "Host {jump_alias}\n\
                                \tHostname {}\n\
                                \tIdentityFile {1}\n\
                                \tCertificateFile {1}-cert.pub\n\
                            \n",
                            proxy_jump,
                            f.identity.display(),
                        );
                        let host_config = format!(
                            "Host *.{} !{jump_alias}\n\
                                \tHostname {}\n\
                                \tProxyJump %r@{}\n\
                                \tIdentityFile {3}\n\
                                \tCertificateFile {3}-cert.pub\n\
                                \tAddKeysToAgent yes\n\
                            \n",
                            &c.alias,
                            &c.hostname,
                            &jump_alias,
                            f.identity.display(),
                        );
                        format!("{}{}", jump_config, host_config)
                    } else {
                        format!(
                            "Host *.{}\n\
                                \tHostname {}\n\
                                \tIdentityFile {2}\n\
                                \tCertificateFile {2}-cert.pub\n\
                                \tAddKeysToAgent yes\n\
                            \n",
                            &c.alias,
                            &c.hostname,
                            f.identity.display(),
                        )
                    }
                })
                .collect::<Vec<String>>()
                .join("");
            let alias_configs = f
                .projects
                .iter()
                .map(|(project, platforms)| {
                    let project_configs = platforms.iter().map(|platform| {
                        let project_alias = format!(
                            "{}.{}",
                            &project,
                            &f.platforms
                                .get(platform)
                                .context("Could not find platform {platform} in config.")?
                                .alias
                        );
                        let project_config = format!(
                            "Host {project_alias}\n\
                            \tUser {}.{}\n",
                            &f.short_name, &project,
                        );
                        Ok(project_config)
                    });
                    Ok(project_configs.collect::<Result<Vec<String>>>()?.join("\n"))
                })
                .collect::<Result<Vec<_>>>()?;
            let config = jump_configs + &alias_configs.join("\n");
            match command {
                Some(SshConfigCommands::Write { ssh_config }) => {
                    let ssh_config = shellexpand::path::tilde(ssh_config);
                    let current_config = std::fs::read_to_string(&ssh_config).unwrap_or_default();
                    let clifton_ssh_config_file = ssh_config.with_file_name("config_clifton");
                    let include_line = format!("Include {}\n", clifton_ssh_config_file.display());
                    if !current_config.contains(&include_line) {
                        let new_config = include_line + &current_config;
                        std::fs::write(&ssh_config, new_config)
                            .context("Could not write main SSH config file.")?;
                    }
                    let text_for_file = "# CLIFTON MANAGED\n".to_string() + &config;
                    std::fs::write(&clifton_ssh_config_file, text_for_file)
                        .context("Could not write clifon SSH config file.")?;
                    println!(
                        "Wrote SSH config to {} and ensured {} includes it\nfor host aliases: \n - {}",
                        &clifton_ssh_config_file.display(),
                        &ssh_config.display(),
                        &f.projects
                            .iter()
                            .flat_map(|(project, platforms)| {
                                platforms.iter().map(|platform| {
                                    Ok(format!(
                                        "{}.{}",
                                        project.clone(),
                                        &f.platforms
                                            .get(platform)
                                            .context("Could not find platform {platform} in config.")?
                                            .alias
                                    ))
                                })
                            })
                            .collect::<Result<Vec<_>>>()?
                            .join("\n - "),
                    );
                }
                None => {
                    eprintln!("Copy this configuration into your SSH config file");
                    eprintln!("or use `clifton ssh-config write`.");
                    eprintln!();
                    println!("{config}");
                }
            }
        }
        Some(Commands::SshCommand { project, platform }) => {
            let f: CertificateConfigCache = serde_json::from_str(
                &cache::read_file(cert_details_file_name).context(
                    "Could not read certificate details cache. Have you run `clifton auth`?",
                )?,
            )
            .context("Could not parse certificate details cache. Try rerunning `clifton auth`.")?;
            if let Some((_, s)) = &f.projects.iter().find(|(p_name, _)| p_name == &project) {
                let platform_name = match s.as_slice() {
                    [] => Err(anyhow::anyhow!("No platforms found for requested project.")),
                    [p] => Ok(p),
                    platforms => {
                        if let Some(platform) = platform {
                            if platforms.contains(platform) {
                                Ok(platform)
                            } else {
                                Err(anyhow::anyhow!("No match."))
                            }
                        } else {
                            Err(anyhow::anyhow!(
                                "Ambiguous project. \
                                It's available on platforms {platforms:?}. \
                                Try specifying the platform with `clifton ssh-command {project} <PLATFORM>`"
                            ))
                        }
                    }
                }
                .context("Could not get platform.")?;
                let platform = f
                    .platforms
                    .get(platform_name)
                    .context(format!("Could not find {} in platforms.", platform_name))?;
                let line = format!(
                    "ssh {}-i '{}' -o 'CertificateFile {}-cert.pub' -o 'AddKeysToAgent yes' {}.{}@{}",
                    if let Some(j) = &platform.proxy_jump {
                        format!("-J '%r@{}' ", j)
                    } else {
                        " ".to_string()
                    },
                    f.identity.display(),
                    f.identity.display(),
                    &f.short_name,
                    &project,
                    &platform.hostname,
                );
                if std::io::stdout().is_terminal() {
                    // OpenSSH does not seem to offer the certificate to the jump host
                    // unless it's in the default search list.
                    eprintln!("Note that if using a non-standard identity file location, the given SSH command may not work.");
                }
                println!("{line}");
            } else {
                anyhow::bail!(format!(
                    "Project {project} does not match any currently authorised for. Try rerunning `clifton auth`."
                ))
            }
        }
        Some(Commands::ClearCache) => cache::delete_all()?,
        None => Args::command().print_help()?,
    }

    // TODO Generate known_hosts line for host certificate
    // TODO Write known_hosts line

    Ok(())
}

/// Get a signed certificate from Waldur
fn get_cert(
    identity: &ssh_key::PrivateKey,
    api_url: &url::Url,
    token: &String,
) -> Result<CertificateSignResponse> {
    let cert_r = reqwest::blocking::Client::new()
        .get(format!("{api_url}sign"))
        .query(&[
            ("public_key", identity.public_key().to_string()),
            ("clifton-version", version().to_string()),
        ])
        .header("Accept", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .context("Could not get certificate from CA.")?;
    if cert_r.status().is_success() {
        let cert = cert_r
            .json::<CertificateSignResponse>()
            .context("Could not parse certificate response from CA. This could be caused by an outdated version of Clifton.")?;
        Ok(cert)
    } else {
        anyhow::bail!(cert_r.text().context("Could not get error message.")?);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Matcher, Server};
    use serde_json::json;

    #[test]
    fn test_get_cert() -> Result<()> {
        let mut server = Server::new();
        let url = server.url().parse()?;

        let private_key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )?;
        let signing_key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )?;
        let certificate = {
            let mut certificate = ssh_key::certificate::Builder::new_with_random_nonce(
                &mut ssh_key::rand_core::OsRng,
                private_key.public_key(),
                0,
                100,
            )?;
            certificate.valid_principal("nobody")?;
            certificate.sign(&signing_key)?
        };

        let mock = server
            .mock("GET", "/sign")
            .match_query(Matcher::UrlEncoded(
                "public_key".into(),
                private_key.public_key().to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "text/json")
            .with_body(
                json!({
                    "platforms": {
                        "plat1": {
                            "alias": "1.example",
                            "hostname": "1.example.com",
                            "proxy_jump": "jump.example.com"
                        }
                    },
                    "short_name": "nobody",
                    "certificate": certificate,
                    "projects": {
                        "proj1": [
                            "plat1",
                            "plat2",
                        ],
                        "proj2": [
                            "plat1",
                        ]
                    },
                    "user": "nobody@example.com",
                    "version": 2,
                })
                .to_string(),
            )
            .create();

        get_cert(&private_key, &url, &"foo".to_string()).context("Cannot call get_cert.")?;
        mock.assert();
        Ok(())
    }
}
