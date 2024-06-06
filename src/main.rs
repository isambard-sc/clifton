// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};
use clap::{CommandFactory as _, Parser, Subcommand};
use md5::Digest;
use serde::Deserialize;

pub mod auth;
pub mod config;

#[derive(Deserialize)]
struct WaldurCertificateSignResponse {
    certificate: String,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
/// Connect to Isambard
struct Args {
    /// Project UUID
    #[arg(long)]
    project: String,

    /// The clifton config file to use
    #[arg(
        long,
        default_value_os_t = dirs::config_local_dir()
            .unwrap_or(
                ".".parse()
                    .expect("Could not parse fallback config directory"),
            )
            .join("clifton")
            .join("config.toml")
    )]
    config_file: std::path::PathBuf,

    /// The SSH public key to use
    #[arg(short = 'k', long)]
    public_key: Option<std::path::PathBuf>,

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
                .expect("Could not find home directory")
                .join(".ssh")
                .join("config")
        )]
        ssh_config: std::path::PathBuf,
    },
}

/// Waldur uses old MD5 fingerprints so we must convert to that format
pub fn fingerprint_md5(key: &ssh_key::PublicKey) -> Result<String> {
    let mut sh = md5::Md5::default();
    sh.update(key.to_bytes()?);
    let md5: Vec<String> = sh.finalize().iter().map(|n| format!("{:02x}", n)).collect();
    Ok(md5.join(":"))
}

fn main() -> Result<()> {
    //let args: Args = argh::from_env();
    let args = Args::try_parse()?;

    let config: config::Config = match std::fs::read_to_string(&args.config_file) {
        Ok(config_string) => toml::from_str(&config_string)?,
        Err(_) => toml::from_str("")?, // TODO raise error if not found
    };

    let public_key_file = args.public_key.as_ref().unwrap_or(&config.public_key);
    if !public_key_file.is_file() {
        anyhow::bail!("Public key file not found")
    }
    let public_key = ssh_key::PublicKey::read_openssh_file(public_key_file.as_path())
        .context("Could not read SSH public key")?;

    let cache_dir = dirs::cache_dir().unwrap_or(".".parse()?).join("clifton");
    let cert_file_name = format!(
        "{}-{}-cert.pub",
        public_key_file
            .file_stem()
            .and_then(|v| v.to_str())
            .unwrap_or("id"),
        args.project
    );
    let cert_file_path = cache_dir.join(cert_file_name);

    match &args.command {
        Some(Commands::Auth {}) => {
            // TODO Get project list. Filter by name and chose if unambiguous
            match cache_dir.try_exists() {
                Ok(true) => (),
                Ok(false) => std::fs::create_dir_all(&cache_dir)
                    .context("Could not create cache directory")?,
                Err(err) => {
                    return Err(err).context("Cound not check for existence of cache directory")
                }
            }
            let key_cache_path = cache_dir.join("waldur_api_key");
            // Try to load the Waldur API key from the cache
            let cert_text = std::fs::read_to_string(&key_cache_path)
                .ok()
                .and_then(|api_key| {
                    // If it's there, try to use it
                    get_cert(&public_key, &config.waldur_api_url, &args.project, &api_key).ok()
                })
                .map_or_else(
                    || {
                        // If the certificate could not be fetched, renew the API token
                        let api_key = get_api_key(&config, &key_cache_path)?;
                        get_cert(&public_key, &config.waldur_api_url, &args.project, &api_key)
                    },
                    Ok,
                )
                .context("Could not get certificate")?;

            std::fs::write(&cert_file_path, cert_text + "\n")
                .context("Could not write certificate file")?;
            println!("Certificate file written to {}", &cert_file_path.display());
        }
        Some(Commands::SshConfig { command }) => {
            let host_alias = format!("{}.{}", &args.project, "ai.isambard");
            let host_config = format!(
                "Host {}\n\tHostname {}\n\tUser {}\n\tCertificateFile {}\n",
                &host_alias,
                "ai.login.isambard.ac.uk", // TODO
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
                    let text_for_file = "\n".to_string() + &host_config;
                    // TODO Work for non-existent config file
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(ssh_config)
                        .context("Could not open SSH config file for writing")?
                        .write_all(text_for_file.as_bytes())
                        .context("Could not write to SSH config file")?;
                    println!(
                        "Written SSH config to {} with Host \"{}\"",
                        &ssh_config.display(),
                        &host_alias
                    );
                }
                None => {
                    eprintln!("Copy this configuration into your SSH config file");
                    eprintln!("or use `clifton ssh-config write`");
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
        .context("Could not get OAuth token")?;
    let api_key = auth::get_waldur_token(&config.waldur_api_url, kc_token)
        .context("Could not get Waldur API token")?;
    let mut f = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        f = f.mode(0o600).clone();
    }
    f.write(true)
        .truncate(true)
        .create(true)
        .open(key_cache_path)
        .context("Could not open cache file")?
        .write_all(api_key.as_bytes())
        .context("Could not write to cache")?;
    Ok(api_key)
}

/// Get a signed certificate from Waldur
fn get_cert(
    public_key: &ssh_key::PublicKey,
    api_url: &url::Url,
    project: &String,
    token: &String,
) -> Result<String> {
    let fingerprint = fingerprint_md5(public_key)
        .context("Could not calculate the MD5 hash of the fingerprint")?;
    let r = reqwest::blocking::Client::new()
        .get(format!("{}/api/projects/{}/cert", api_url, project))
        .query(&[("fingerprint", fingerprint)])
        .header("Accept", "application/json")
        .header("Authorization", format!("Token {}", token))
        .send()
        .context("Could not get certificate from Waldur")?;
    let cert_text = r
        .json::<WaldurCertificateSignResponse>()
        .context("Could not parse cetificate response from Waldur")?
        .certificate;
    Ok(cert_text)
}
