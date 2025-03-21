// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use cert::{Associations, CertificateConfigCache, CertificateSignResponse};
use clap::{CommandFactory as _, Parser, Subcommand};
use itertools::Itertools;
use std::io::IsTerminal;

use crate::auth::get_access_token;
use crate::cert::CaOidcResponse;

pub mod auth;
pub mod cache;
pub mod cert;
pub mod config;
mod version;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

fn version() -> &'static str {
    built_info::GIT_VERSION.unwrap_or(built_info::PKG_VERSION)
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
        ),
        global=true,
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
        /// The resource to access the project on
        resource: Option<String>,
    },
    /// Empty the cache
    #[command(hide = true)]
    ClearCache,
    /// Manage the config
    #[command(hide = true)]
    Config,
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
            "https://github.com/isambard-sc/clifton/releases.atom".parse()?,
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
            let identity_file = std::path::absolute(shellexpand::path::tilde(
                identity
                    .as_ref()
                    .or(config.identity.as_ref())
                    .context("No identity file specified.")?,
            ))
            .context("Could not form absolute path for the identity file.")?;
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

            let site_name = config.default_site;
            let site = config
                .sites
                .get(&site_name)
                .context(format!("Could not get site details for `{site_name}`."))?;
            let oidc_details: CaOidcResponse =
                reqwest::blocking::get(format!("{}oidc", &site.ca_url))
                    .context("Could not get CA OIDC details.")?
                    .error_for_status()
                    .context("Could not get CA OIDC details.")?
                    .json()
                    .context("Could not parse CA OIDC details as URL.")?;

            let cert_file_path = identity_file.with_file_name(
                [
                    identity_file
                        .file_name()
                        .context("Could not understand identity file name.")?,
                    std::ffi::OsStr::new("-cert.pub"),
                ]
                .join(std::ffi::OsStr::new("")),
            );
            println!(
                "Retrieving certificate for identity `{}`.",
                &identity_file.display()
            );
            let cert = {
                let token = get_access_token(
                    &oidc_details.client_id,
                    &oidc_details.issuer,
                    open_browser,
                    show_qr,
                )?;
                get_cert(&identity, &site.ca_url, token.secret())
            };
            let cert = match cert {
                Ok(cert) => cert,
                Err(e) => {
                    cache::delete_file(cert_details_file_name).unwrap_or_default();
                    anyhow::bail!(e)
                }
            };
            let certificate = match &cert {
                CertificateSignResponse::V2(r) => &r.certificate,
                CertificateSignResponse::V3(r) => &r.certificate,
            };
            std::fs::write(
                &cert_file_path,
                format!(
                    "{}\n",
                    &certificate
                        .to_openssh()
                        .context("Could not convert certificate to OpenSSH format.")?
                ),
            )
            .context("Could not write certificate file.")?;
            let green = anstyle::Style::new()
                .fg_color(Some(anstyle::AnsiColor::Green.into()))
                .bold();
            let cert_config_cache =
                CertificateConfigCache::from_response(&cert, identity_file.to_path_buf());
            match &cert_config_cache.associations {
                Associations::Projects(projects) => match projects.len() {
                    0 => {
                        anyhow::bail!("Did not authenticate with any projects.")
                    }
                    _ => {
                        let projects = projects
                            .iter()
                            .map(|(p_id, p)| {
                                match p.name.as_str() {
                                    "" => format!("- {}", &p_id),
                                    name => format!(" - {} ({})", &p_id, name),
                                }
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        println!(
                                    "{green}Successfully authenticated as {} and downloaded SSH certificate for projects{green:#}:\n{projects}\n",
                                    &cert_config_cache.user
                                );
                    }
                },
                Associations::Resources(_resources) => println!(
                                    "{green}Successfully authenticated as {} and downloaded SSH certificate.{green:#}",
                                    &cert_config_cache.user
                                ),
            }
            type Tz = chrono::offset::Utc; // TODO This is UNIX time, not UTC
            let valid_before: chrono::DateTime<Tz> = certificate.valid_before_time().into();
            let valid_for = valid_before - Tz::now();
            cache::write_file(
                cert_details_file_name,
                serde_json::to_string(&cert_config_cache)?,
            )
            .context("Could not write certificate details cache.")?;
            println!("Certificate file written to {}", &cert_file_path.display());
            println!(
                "Certificate valid for {} hours and {} minutes.",
                valid_for.num_hours(),
                valid_for.num_minutes() % 60,
            );
            let clifton_ssh_config_path = dirs::home_dir()
                .context("")?
                .join(".ssh")
                .join("config_clifton");
            if cert_config_cache.ssh_config()?
                != std::fs::read_to_string(&clifton_ssh_config_path).unwrap_or_default()
            {
                let bold = anstyle::Style::new().bold();
                println!(
                    "\n{bold}Config appears to have changed.\nYou may now want to run `clifton ssh-config write` to configure your SSH config aliases.{bold:#}"
                );
            }
        }
        Some(Commands::SshConfig { command }) => {
            let f: CertificateConfigCache = serde_json::from_str(
                &cache::read_file(cert_details_file_name).context(
                    "Could not read certificate details cache. Have you run `clifton auth`?",
                )?,
            )
            .context("Could not parse certificate details cache. Try rerunning `clifton auth`.")?;
            let config = &f.ssh_config()?;
            match command {
                Some(SshConfigCommands::Write { ssh_config }) => {
                    let main_ssh_config_path = shellexpand::path::tilde(ssh_config);
                    let current_main_config =
                        std::fs::read_to_string(&main_ssh_config_path).unwrap_or_default();
                    let clifton_ssh_config_path =
                        main_ssh_config_path.with_file_name("config_clifton");
                    let include_line =
                        format!("Include \"{}\"\n", clifton_ssh_config_path.display());
                    if !current_main_config.contains(&include_line) {
                        let new_config = include_line + &current_main_config;
                        std::fs::write(&main_ssh_config_path, new_config)
                            .context("Could not write Include line to main SSH config file.")?;
                        println!(
                            "Updated {} to contain Include line.",
                            &main_ssh_config_path.display()
                        );
                    }

                    let current_clifton_config =
                        std::fs::read_to_string(&clifton_ssh_config_path).unwrap_or_default();
                    if config == &current_clifton_config {
                        println!("SSH config is already up to date.");
                    } else {
                        std::fs::write(&clifton_ssh_config_path, config)
                            .context("Could not write clifon SSH config file.")?;
                        println!(
                            "Wrote SSH config to {}.",
                            &clifton_ssh_config_path.display()
                        );
                    }
                    println!(
                        "Available host aliases: \n - {}",
                        match &f.associations {
                            Associations::Projects(projects) => projects
                                .iter()
                                .flat_map(|(project_id, project)| {
                                    project.resources.keys().map(|resource_id| {
                                        Ok(format!(
                                            "{}.{}",
                                            project_id.clone(),
                                            &f.resource(resource_id)?.alias
                                        ))
                                    })
                                })
                                .collect::<Result<Vec<_>>>()?
                                .join("\n - "),
                            Associations::Resources(resources) => {
                                resources
                                    .keys()
                                    .map(|resource_id| Ok(&f.resource(resource_id)?.alias))
                                    .collect::<Result<Vec<_>>>()?
                                    .into_iter()
                                    .join("\n - ")
                            }
                        }
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
        Some(Commands::SshCommand { project, resource }) => {
            let f: CertificateConfigCache = serde_json::from_str(
                &cache::read_file(cert_details_file_name).context(
                    "Could not read certificate details cache. Have you run `clifton auth`?",
                )?,
            )
            .context("Could not parse certificate details cache. Try rerunning `clifton auth`.")?;
            if let Some(s) = match &f.associations {
                Associations::Projects(projects) => projects
                    .iter()
                    .find(|(p_name, _)| p_name == &project)
                    .map(|p| p.1.resources.clone()),
                Associations::Resources(resources) => Some(resources).cloned(),
            } {
                let (resource_id, resource_association) = match s.len() {
                    2.. => {
                        if let Some(resource) = resource {
                            s.iter().find(|(resource_id, _)| *resource_id == resource).context("No matching resource.")
                        } else {
                            Err(anyhow::anyhow!(
                                "Ambiguous project. \
                                It's available on resources {s:?}. \
                                Try specifying the resource with `clifton ssh-command {project} <RESOURCE>`"
                            ))
                        }
                    }
                    _ => s.iter().next().ok_or(anyhow::anyhow!("No resources found for requested project.")),
                }
                .context("Could not get resource.")?;
                let resource = f.resource(resource_id).context(format!(
                    "Could not find {} in list of resources.",
                    resource_id
                ))?;
                let line = format!(
                    "ssh {}-i '{}' -o 'CertificateFile \"{}-cert.pub\"' -o 'AddKeysToAgent yes' {}.{}@{}",
                    if let Some(j) = &resource.proxy_jump {
                        format!("-J '%r@{}' ", j)
                    } else {
                        " ".to_string()
                    },
                    f.identity.display(),
                    f.identity.display(),
                    &resource_association.username,
                    &project,
                    &resource.hostname,
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
        Some(Commands::Config) => {
            println!("{}", default_config_path().display());
        }
        None => Args::command().print_help()?,
    }

    // TODO Generate known_hosts line for host certificate
    // TODO Write known_hosts line

    Ok(())
}

/// Get a signed certificate from CA
fn get_cert(
    identity: &ssh_key::PrivateKey,
    api_url: &url::Url,
    token: &String,
) -> Result<CertificateSignResponse> {
    let cert_r = reqwest::blocking::Client::builder()
        .user_agent(format!(
            "Clifton/{} (os:{}) (arch:{})",
            version(),
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
        .build()
        .context("Could not build HTTP client.")?
        .get(format!("{api_url}sign"))
        .query(&[("public_key", identity.public_key().to_string())])
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
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
                        },
                        "plat2": {
                            "alias": "2.example",
                            "hostname": "2.example.com",
                            "proxy_jump": "jump.example.com"
                        },
                    },
                    "short_name": "foo",
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

        let cert =
            get_cert(&private_key, &url, &"foo".to_string()).context("Cannot call get_cert.")?;
        mock.assert();
        let cert = CertificateConfigCache::from_response(&cert, "/foo/bar".into());
        let config = cert.ssh_config()?;
        assert!(config.contains("Host proj1.1.example\n\tUser foo.proj1"));
        assert!(config.contains("Host proj1.2.example\n\tUser foo.proj1"));
        assert!(config.contains("Host proj2.1.example\n\tUser foo.proj2"));
        assert!(!config.contains("proj2.2.example"));

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
                    "resources": {
                        "plat1": {
                            "alias": "1.example",
                            "hostname": "1.example.com",
                            "proxy_jump": "jump.example.com"
                        },
                        "plat2": {
                            "alias": "2.example",
                            "hostname": "2.example.com",
                            "proxy_jump": "jump.example.com"
                        },
                    },
                    "certificate": certificate,
                    "associations": {
                        "projects": {
                            "proj1": {
                                "name" : "Foo project",
                                "resources" : {
                                    "plat1": {
                                        "username": "foo.1",
                                    },
                                    "plat2": {
                                        "username": "foo.2",
                                    },
                                }
                            },
                            "proj2": {
                                "name" : "Bar project",
                                "resources" : {
                                    "plat1": {
                                        "username": "foo.1",
                                    },
                                }
                            },
                        },
                    },
                    "user": "nobody@example.com",
                    "version": 3,
                })
                .to_string(),
            )
            .create();

        let cert =
            get_cert(&private_key, &url, &"foo".to_string()).context("Cannot call get_cert.")?;
        mock.assert();
        let cert = CertificateConfigCache::from_response(&cert, "/foo/bar".into());
        let config = cert.ssh_config()?;
        assert!(config.contains("Host proj1.1.example\n\tUser foo.1"));
        assert!(config.contains("Host proj1.2.example\n\tUser foo.2"));
        assert!(config.contains("Host proj2.1.example\n\tUser foo.1"));
        assert!(!config.contains("proj2.2.example"));

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
                    "resources": {
                        "plat1": {
                            "alias": "1.example",
                            "hostname": "1.example.com",
                            "proxy_jump": "jump.example.com"
                        },
                        "plat2": {
                            "alias": "2.example",
                            "hostname": "2.example.com",
                            "proxy_jump": "jump.example.com"
                        },
                    },
                    "certificate": certificate,
                    "associations": {
                        "resources": {
                            "plat1": {
                                "username": "foo.1",
                            },
                            "plat2": {
                                "username": "foo.2",
                            },
                        },
                    },
                    "user": "nobody@example.com",
                    "version": 3,
                })
                .to_string(),
            )
            .create();

        let cert =
            get_cert(&private_key, &url, &"foo".to_string()).context("Cannot call get_cert.")?;
        mock.assert();
        let cert = CertificateConfigCache::from_response(&cert, "/foo/bar".into());
        let config = cert.ssh_config()?;
        assert!(config.contains("Host 1.example\n\tUser foo.1"));
        assert!(config.contains("Host 2.example\n\tUser foo.2"));

        Ok(())
    }
}
