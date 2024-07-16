// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use std::io::{IsTerminal, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};
use clap::{CommandFactory as _, Parser, Subcommand};
use md5::Digest;
use serde::{Deserialize, Serialize};

pub mod auth;
pub mod config;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

fn version() -> &'static str {
    built_info::GIT_VERSION.unwrap_or(built_info::PKG_VERSION)
}

#[derive(Deserialize)]
struct WaldurCertificateSignResponse {
    certificate: String,
    #[serde(with = "http_serde::authority")]
    hostname: http::uri::Authority,
    #[serde(with = "http_serde::authority")]
    proxy_jump: http::uri::Authority,
    service: String,
    projects: Vec<ProjectDetails>,
    user: String,
    version: u32,
}

#[derive(Deserialize, Serialize)]
struct ProjectDetails {
    short_name: String,
    username: String,
}

#[derive(Deserialize, Serialize)]
struct CertificateConfigCache {
    #[serde(with = "http_serde::authority")]
    hostname: http::uri::Authority,
    #[serde(with = "http_serde::authority")]
    proxy_jump: http::uri::Authority,
    service: String,
    projects: Vec<ProjectDetails>,
    user: String,
    identity: std::path::PathBuf,
}

impl CertificateConfigCache {
    fn from_reponse(r: WaldurCertificateSignResponse, identity: std::path::PathBuf) -> Self {
        CertificateConfigCache {
            hostname: r.hostname,
            proxy_jump: r.proxy_jump,
            service: r.service,
            projects: r.projects,
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
        /// The SSH identity (private key) to use. Should be a path like ~/.ssh/id_id_ed25519
        #[arg(short = 'i', long)]
        identity: Option<std::path::PathBuf>,
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
    },
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

/// Waldur uses old MD5 fingerprints so we must convert to that format
pub fn fingerprint_md5(key: &ssh_key::PrivateKey) -> Result<String> {
    let mut sh = md5::Md5::default();
    sh.update(key.public_key().to_bytes()?);
    let md5: Vec<String> = sh.finalize().iter().map(|n| format!("{:02x}", n)).collect();
    Ok(md5.join(":"))
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
            Ok(true) => f,
            Ok(false) => anyhow::bail!(format!("Config file `{}` not found.", &f.display())),
            Err(err) => return Err(err).context("Could not dertmine if config file exists."),
        },
        None => &default_config_path(),
    };

    let config: config::Config = match std::fs::read_to_string(config_file_path) {
        Ok(config_string) => toml::from_str(&config_string)?,
        Err(_) => toml::from_str("")?,
    };

    // Set up cache
    let cache_dir = dirs::cache_dir().unwrap_or(".".parse()?).join("clifton");
    let cert_details_file_path = cache_dir.join("cert.json");

    match &args.command {
        Some(Commands::Auth { identity }) => {
            // Load the user's public key
            let identity_file = identity.as_ref().unwrap_or(&config.identity);
            if !identity_file.is_file() {
                anyhow::bail!(format!(
                    "Identity file {} not found.\nEither specify the identity file (see `clifton auth --help`) or create a new key.",
                    &identity_file.display(),
                ))
            }
            let identity = ssh_key::PrivateKey::read_openssh_file(identity_file.as_path())
                .context("Could not read SSH identity file")?;

            let cert_file_path = identity_file.with_file_name(
                [
                    identity_file
                        .file_name()
                        .context("Could not understand identity file name")?,
                    std::ffi::OsStr::new("-cert.pub"),
                ]
                .join(std::ffi::OsStr::new("")),
            );
            match cache_dir.try_exists() {
                Ok(true) => (),
                Ok(false) => std::fs::create_dir_all(&cache_dir)
                    .context("Could not create cache directory.")?,
                Err(err) => {
                    return Err(err).context("Cound not check for existence of cache directory.")
                }
            }
            let key_cache_path = cache_dir.join("waldur_api_key");
            // Try to load the Waldur API key from the cache
            let cert = std::fs::read_to_string(&key_cache_path)
                .ok()
                .and_then(|api_key| {
                    // If it's there, try to use it
                    get_cert(&identity, &config.waldur_api_url, &api_key).ok()
                })
                .map_or_else(
                    || {
                        // If the certificate could not be fetched, renew the API token
                        let api_key = get_api_key(&config, &key_cache_path)?;
                        get_cert(&identity, &config.waldur_api_url, &api_key)
                    },
                    Ok,
                )
                .context("Could not get certificate.")?;
            match cert.projects.as_slice() {
                [p] => {
                    println!(
                        "Authenticated as {} for project {}\n",
                        &cert.user, p.short_name
                    );
                }
                projects @ [_, ..] => {
                    let projects = projects
                        .iter()
                        .map(|p| format!(" - {}", &p.short_name))
                        .collect::<Vec<_>>()
                        .join("\n");
                    println!(
                        "Authenticated as {} for projects:\n{}\n",
                        &cert.user, projects
                    );
                }
                [] => {
                    anyhow::bail!("Did not authenticate with any projects.")
                }
            }
            std::fs::write(&cert_file_path, format!("{}\n", &cert.certificate))
                .context("Could not write certificate file.")?;
            // TODO delete cache on failed auth
            std::fs::write(
                &cert_details_file_path,
                serde_json::to_string(&CertificateConfigCache::from_reponse(
                    cert,
                    identity_file.clone(),
                ))?,
            )
            .context("Could not write certificate details cache.")?;
            println!("Certificate file written to {}", &cert_file_path.display());
        }
        Some(Commands::SshConfig { command }) => {
            let f: CertificateConfigCache = serde_json::from_str(
                &std::fs::read_to_string(&cert_details_file_path).context(
                    "Could not read certificate details cache. Have you run `clifton auth`?",
                )?,
            )
            .context("Could not parse certificate details cache. Try rerunning `clifton auth`.")?;
            let jump_alias = format!("jump.{}", &f.service);
            let jump_config = format!(
                "Host {}\n\tHostname {}\n\tIdentityFile {}\n\tCertificateFile {}-cert.pub\n\n",
                &jump_alias,
                f.proxy_jump,
                f.identity.display(),
                f.identity.display(),
            );
            let alias_configs = f.projects.iter().map(|p| {
                let host_alias = format!("{}.{}", &p.short_name, &f.service);
                let host_config = format!(
                    "Host {}\n\tHostname {}\n\tProxyJump %r@{}\n\tUser {}\n\tIdentityFile {}\n\tCertificateFile {}-cert.pub\n\tAddKeysToAgent yes\n",
                    &host_alias,
                    f.hostname,
                    &jump_alias,
                    p.username,
                    f.identity.display(),
                    f.identity.display(),
                );
                Ok(host_config)
            }).collect::<Result<Vec<_>>>()?;
            let config = jump_config + &alias_configs.join("\n");
            match command {
                Some(SshConfigCommands::Write { ssh_config }) => {
                    // TODO allow tilde in custom path
                    let current_config = std::fs::read_to_string(ssh_config).unwrap_or_default();
                    let clifton_ssh_config_file = ssh_config.with_file_name("config_clifton");
                    let include_line = format!("Include {}\n", clifton_ssh_config_file.display());
                    if !current_config.contains(&include_line) {
                        let new_config = include_line + &current_config;
                        std::fs::write(ssh_config, new_config)
                            .context("Could not write main SSH config file.")?
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
                            .map(|p| format!("{}.{}", &p.short_name, &f.service))
                            .collect::<Vec<_>>()
                            .join("\n - "),
                    );
                }
                None => {
                    eprintln!("Copy this configuration into your SSH config file");
                    eprintln!("or use `clifton ssh-config write`.");
                    eprintln!();
                    println!("{}", &config);
                }
            }
        }
        Some(Commands::SshCommand { project }) => {
            let f: CertificateConfigCache =
                serde_json::from_str(&std::fs::read_to_string(&cert_details_file_path).context(
                    "Could not read certificate details cache. Have you run `clifton auth`?",
                )?)
                .context("Could not parse certificate details cache.")?;
            if let Some(p) = &f.projects.iter().find(|p| &p.short_name == project) {
                let line = format!(
                    "ssh -J '%r@{}' -i '{}' -o 'CertificateFile {}-cert.pub' -o 'AddKeysToAgent yes' {}@{}",
                    &f.proxy_jump,
                    f.identity.display(),
                    f.identity.display(),
                    &p.username,
                    &f.hostname,
                );
                if std::io::stdout().is_terminal() {
                    // OpenSSH does not seem to offer the certificate to the jump host
                    // unless it's in the default search list.
                    eprintln!("Note that if using a non-standard identity file location, the given SSH command may not work.");
                }
                println!("{}", line);
            } else {
                anyhow::bail!(format!(
                    "Project {} does not match any currently authorised for. Try rerunning `clifton auth`.",
                    project
                ))
            }
        }
        None => Args::command().print_help()?,
    }

    // TODO Generate known_hosts line for host certificate
    // TODO Write known_hosts line

    Ok(())
}

/// Do the full authentication pathway with OAuth and Waldur to get
/// the Waldur API token. Finally, cache it.
fn get_api_key(
    config: &config::Config,
    key_cache_path: &std::path::PathBuf,
) -> Result<String, anyhow::Error> {
    let kc_token = auth::get_keycloak_token(&config.client_id, &config.keycloak_url, true)
        .context("Could not get OAuth token.")?;
    let api_key = auth::get_waldur_token(&config.waldur_api_url, kc_token)
        .context("Could not get Waldur API token.")?;
    let mut f = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        f = f.mode(0o600).clone();
    }
    f.write(true)
        .truncate(true)
        .create(true)
        .open(key_cache_path)
        .context("Could not open cache file.")?
        .write_all(api_key.as_bytes())
        .context("Could not write to cache.")?;
    Ok(api_key)
}

/// Get a signed certificate from Waldur
fn get_cert(
    identity: &ssh_key::PrivateKey,
    api_url: &url::Url,
    token: &String,
) -> Result<WaldurCertificateSignResponse> {
    let fingerprint =
        fingerprint_md5(identity).context("Could not calculate the MD5 hash of the fingerprint")?;
    let cert_r = reqwest::blocking::Client::new()
        .get(format!("{}api/users/me/cert", &api_url))
        .query(&[
            ("fingerprint", fingerprint),
            ("clifton-version", version().to_string()),
        ])
        .header("Accept", "application/json")
        .header("Authorization", format!("Token {}", token))
        .send()
        .context("Could not get certificate from Waldur.")?;
    if cert_r.status().is_success() {
        let cert = cert_r
            .json::<WaldurCertificateSignResponse>()
            .context("Could not parse certificate response from Waldur.")?;
        Ok(cert)
    } else {
        anyhow::bail!(cert_r.text().context("Could not get error message.")?);
    }
}
