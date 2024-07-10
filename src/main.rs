// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use std::io::Write;
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

#[derive(Deserialize, Serialize)]
struct WaldurCertificateSignResponse {
    certificate: String,
    #[serde(with = "http_serde::authority")]
    hostname: http::uri::Authority,
    #[serde(with = "http_serde::authority")]
    proxy_jump: http::uri::Authority,
}

#[derive(Deserialize)]
struct WaldurProjectResponse {
    url: String,
    name: String,
    short_name: String,
}

#[derive(Parser)]
#[command(version = built_info::GIT_VERSION.expect("Could not find version."), about, long_about = None)]
/// Connect to Isambard
struct Args {
    /// Project short name
    #[arg(long)]
    project: String,

    #[arg(
        long,
        help=format!(
            "The clifton config file to use [default: {}]",
            &default_config_path().display(),
        )
    )]
    config_file: Option<std::path::PathBuf>,

    /// The SSH identity to use
    #[arg(short = 'i', long)]
    identity: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate and retrieve signed SSH certificate
    Auth {},
    /// Display the OpenSSH config
    SshConfig {
        /// Generate the SSH config snippet
        #[command(subcommand)]
        command: Option<SshConfigCommands>,
    },
}

#[derive(Subcommand)]
enum SshConfigCommands {
    /// Write the config to the SSH config
    Write {
        /// The SSH config file to write to
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

    // Load the user's public key
    let identity_file = args.identity.as_ref().unwrap_or(&config.identity);
    if !identity_file.is_file() {
        anyhow::bail!(format!(
            "Identity file {} not found",
            &identity_file.display()
        ))
    }
    let identity = ssh_key::PrivateKey::read_openssh_file(identity_file.as_path())
        .context("Could not read SSH identity file")?;

    // Set up cache
    let cache_dir = dirs::cache_dir().unwrap_or(".".parse()?).join("clifton");
    let cert_file_path = identity_file.with_file_name(
        [
            identity_file
                .file_name()
                .context("Could not understand identity file name")?,
            std::ffi::OsStr::new("-cert.pub"),
        ]
        .join(std::ffi::OsStr::new("")),
    );
    let cert_details_file_path = cache_dir.join(format!("{}.json", &args.project));

    match &args.command {
        Some(Commands::Auth {}) => {
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
                    get_cert(&identity, &config.waldur_api_url, &args.project, &api_key).ok()
                })
                .map_or_else(
                    || {
                        // If the certificate could not be fetched, renew the API token
                        let api_key = get_api_key(&config, &key_cache_path)?;
                        get_cert(&identity, &config.waldur_api_url, &args.project, &api_key)
                    },
                    Ok,
                )
                .context("Could not get certificate.")?;
            // TODO set permissions
            std::fs::write(&cert_file_path, format!("{}\n", &cert.certificate))
                .context("Could not write certificate file.")?;
            std::fs::write(&cert_details_file_path, serde_json::to_string(&cert)?)
                .context("Could not write certificate details cache.")?;
            println!("Certificate file written to {}", &cert_file_path.display());
        }
        Some(Commands::SshConfig { command }) => {
            let f: WaldurCertificateSignResponse =
                serde_json::from_str(&std::fs::read_to_string(&cert_details_file_path).context(
                    "Could not read certificate details cache. Have you run `clifton auth`?",
                )?)
                .context("Could not parse certificate details cache.")?;
            let host_alias = format!("{}.{}", &args.project, "ai.isambard"); // TODO read from portal
            let host_config = format!(
                "Host {}\n\tHostname {}\n\tProxyJump %r@{}\n\tUser {}\n\tCertificateFile {}\n\tForwardAgent yes\n\tAddKeysToAgent yes\n",
                &host_alias,
                f.hostname,
                f.proxy_jump,
                ssh_key::Certificate::read_file(&cert_file_path)
                    .context(format!(
                        "Cannot read certificate file at {}. Have you run `clifton auth`?",
                        &cert_file_path.display()
                    ))?
                    .valid_principals()[0],
                &cert_file_path.display(),
            );
            match command {
                Some(SshConfigCommands::Write { ssh_config }) => {
                    // TODO See if already present and update if so
                    let text_for_file = "\n".to_string() + &host_config;
                    // TODO Work for non-existent config file
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(ssh_config)
                        .context("Could not open SSH config file for writing.")?
                        .write_all(text_for_file.as_bytes())
                        .context("Could not write to SSH config file.")?;
                    println!(
                        "Written SSH config to {} with Host \"{}\"",
                        &ssh_config.display(),
                        &host_alias
                    );
                }
                None => {
                    eprintln!("Copy this configuration into your SSH config file");
                    eprintln!("or use `clifton ssh-config write`.");
                    eprintln!();
                    println!("{}", host_config);
                }
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
    project: &String,
    token: &String,
) -> Result<WaldurCertificateSignResponse> {
    let fingerprint =
        fingerprint_md5(identity).context("Could not calculate the MD5 hash of the fingerprint")?;
    let project_r = reqwest::blocking::Client::new()
        .get(format!("{}api/projects/?short_name={}", api_url, project))
        // .get(format!("{}api/projects/", api_url))
        .header("Accept", "application/json")
        .header("Authorization", format!("Token {}", token))
        .send()
        .context("Could not get project details from Waldur.")?;
    let projects = project_r
        .json::<Vec<WaldurProjectResponse>>()
        .context("Could not parse projects response from Waldur.")?;
    let project = &projects
        .first()
        .context("Did not return a matching project.")?;
    println!(
        "Retrieving key for project \"{}\" ({})",
        &project.name, &project.short_name
    );
    let cert_r = reqwest::blocking::Client::new()
        .get(format!("{}cert", &project.url))
        .query(&[("fingerprint", fingerprint)])
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