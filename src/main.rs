// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use cert::{AssociationsCache, CertificateConfigCache, CertificateSignResponse};
use clap::{CommandFactory as _, Parser, Subcommand};
use itertools::Itertools;
use std::io::{IsTerminal, Write as _};

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
        /// Should the config be written out automatically
        #[arg(long)]
        write_config: Option<bool>,
    },
    /// Display the OpenSSH config
    SshConfig {
        /// Generate the SSH config snippet
        #[command(subcommand)]
        command: Option<SshConfigCommands>,
    },
    /// Display the SSH command line to use for each project.
    /// Note that the given command may not work for non-standard identity file locations.
    #[command(hide = true)]
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

    let config: config::Config = match std::fs::read_to_string(&config_file_path) {
        Ok(config_string) => toml::from_str(&config_string)?,
        Err(_) => toml::from_str("")?,
    };

    if config.check_version {
        let grace_days = 5;
        if let Err(e) = version::check_for_new_version(
            "https://github.com/isambard-sc/clifton/releases.atom".parse()?,
            grace_days,
        )
        .context("Failed to check for new version of Clifton.")
        {
            eprintln!("{:}", &e);
        }
    }

    let site_name = config.default_site;
    let cert_details_file_name = format!("{}.json", &site_name);

    match &args.command {
        Some(Commands::Auth {
            identity,
            open_browser,
            show_qr,
            write_config,
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
            let clifton_name = std::env::current_exe()
                .ok()
                .and_then(|p| p.file_name().map(|f| f.display().to_string()))
                .unwrap_or("clifton".to_string());
            if !identity_file.is_file() {
                anyhow::bail!(format!(
                    "Identity file {} not found.\nEither specify the identity file (see `{} auth --help`) or create a new key.",
                    &identity_file.display(),
                    clifton_name,
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
                    .context("Could not fetch certificate.")
            };
            let cert = match cert {
                Ok(cert) => cert,
                Err(e) => {
                    cache::delete_file(cert_details_file_name).unwrap_or_default();
                    anyhow::bail!(e)
                }
            };
            let green = anstyle::Style::new()
                .fg_color(Some(anstyle::AnsiColor::Green.into()))
                .bold();
            let certificate_dir = cache::cache_dir()?;
            let cert_config_cache = cert.cache(identity_file.to_path_buf(), &certificate_dir)?;
            match &cert_config_cache.associations {
                AssociationsCache::Projects(projects) => match projects.len() {
                    0 => {
                        anyhow::bail!("Did not authenticate with any projects.")
                    }
                    _ => {
                        let project_name_list = projects
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
                            "\n{green}Successfully authenticated as {} and downloaded SSH certificate for projects{green:#}:\n{project_name_list}",
                            &cert_config_cache.user
                        );
                    }
                },
                AssociationsCache::Resources(_resources) => println!(
                    "\n{green}Successfully authenticated as {} and downloaded SSH certificate.{green:#}",
                    &cert_config_cache.user
                ),
            }
            cache::write_file(
                cert_details_file_name,
                serde_json::to_string(&cert_config_cache)?,
            )
            .context("Could not write certificate details cache.")?;

            // We are, in prinicple, returned many certificates. Find the one with the soonest expiry time and print it.
            let first_expiry = match &cert_config_cache.associations {
                AssociationsCache::Projects(projects) => projects
                    .values()
                    .filter_map(|p| {
                        p.resources
                            .iter()
                            .filter_map(|(_, ra)| {
                                ssh_key::Certificate::read_file(ra.certificate.as_path()).ok()
                            })
                            .map(|cert| cert.valid_before_time())
                            .min()
                    })
                    .min(),
                AssociationsCache::Resources(resources) => resources
                    .values()
                    .filter_map(|ra| ssh_key::Certificate::read_file(ra.certificate.as_path()).ok())
                    .map(|cert| cert.valid_before_time())
                    .min(),
            };
            if let Some(first_expiry) = first_expiry {
                type Tz = chrono::offset::Utc; // TODO This is UNIX time, not UTC
                let valid_before: chrono::DateTime<Tz> = first_expiry.into();
                let valid_for = valid_before - Tz::now();
                println!(
                    "Certificate valid for {} hours and {} minutes.",
                    valid_for.num_hours(),
                    valid_for.num_minutes() % 60,
                );
            }

            let clifton_ssh_config_path = dirs::home_dir()
                .context("")?
                .join(".ssh")
                .join("config_clifton");
            let ssh_config = cert_config_cache.ssh_config()?;
            if ssh_config != std::fs::read_to_string(&clifton_ssh_config_path).unwrap_or_default() {
                if write_config.unwrap_or(config.write_config) {
                    ssh_config_write(
                        &clifton_ssh_config_path,
                        &cert_config_cache.ssh_config()?,
                        cert_config_cache,
                    )?;
                } else {
                    let bold = anstyle::Style::new().bold();
                    println!(
                        "\n{bold}SSH config appears to have changed.\nYou may now want to run `{} ssh-config write` to configure your SSH config aliases.{bold:#}",
                        std::env::args().next().unwrap_or("clifton".to_string()),
                    );
                }
            } else if write_config.unwrap_or(config.write_config) {
                print_available_aliases(cert_config_cache)?;
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
                    ssh_config_write(ssh_config, config, f)?;
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
                AssociationsCache::Projects(projects) => projects
                    .iter()
                    .find(|(p_name, _)| p_name == &project)
                    .map(|p| p.1.resources.clone()),
                AssociationsCache::Resources(resources) => Some(resources).cloned(),
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
            println!("{}", &config_file_path.display());
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
        let error_string = cert_r
            .text()
            .context("Could not get error message from server.")?;

        #[derive(serde::Deserialize)]
        struct ErrorResponse {
            message: String,
        }

        let error_message = serde_json::from_str::<ErrorResponse>(&error_string)
            .map_or(error_string, |e| e.message);
        Err(anyhow::anyhow!(error_message).context("Error returned by certificate server."))
    }
}

fn ssh_config_write(
    ssh_config: &std::path::PathBuf,
    config: &String,
    f: CertificateConfigCache,
) -> Result<()> {
    let main_ssh_config_path = shellexpand::path::tilde(ssh_config);
    let current_main_config = std::fs::read_to_string(&main_ssh_config_path).unwrap_or_default();
    let clifton_ssh_config_path = main_ssh_config_path.with_file_name("config_clifton");
    let include_line = format!("Include \"{}\"\n", clifton_ssh_config_path.display());
    if !current_main_config.contains(&include_line) {
        // Remove the old non-quoted format of the Include line
        // This should be kept for a few versions
        let current_main_config = current_main_config
            .split(&format!("Include {}\n", clifton_ssh_config_path.display()))
            .join("");
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
        let mut f = std::fs::OpenOptions::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;

            f = f.mode(0o644).clone(); // u=rw,g=r,o=r
        }
        f.write(true)
            .truncate(true)
            .create(true)
            .open(&clifton_ssh_config_path)
            .context(format!(
                "Could not open clifton SSH config file `{}`.",
                &clifton_ssh_config_path.display()
            ))?
            .write_all(config.as_ref())
            .context("Could not write clifton SSH config file.")?;
        println!(
            "Wrote SSH config to {}.",
            &clifton_ssh_config_path.display()
        );
    }
    print_available_aliases(f)?;

    Ok(())
}

fn print_available_aliases(f: CertificateConfigCache) -> Result<()> {
    println!("\nAvailable SSH host aliases:");
    match &f.associations {
        AssociationsCache::Projects(projects) => projects
            .iter()
            .sorted_by_key(|x| x.0)
            .try_for_each(|(project_id, project)| {
                if !&project.name.is_empty() {
                    println!("{}", project.name);
                }
                project
                    .resources
                    .keys()
                    .sorted()
                    .try_for_each(|resource_id| {
                        println!(
                            " - {}.{}",
                            project_id.clone(),
                            &f.resource(resource_id)?.alias
                        );
                        Ok(())
                    })
            }),
        AssociationsCache::Resources(resources) => {
            resources.keys().sorted().try_for_each(|resource_id| {
                println!(" - {}", &f.resource(resource_id)?.alias);
                Ok(())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Matcher, Server};
    use rand::distr::{Alphanumeric, SampleString};
    use serde_json::json;
    use ssh2_config::{ParseRule, SshConfig};

    #[rstest::fixture]
    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(std::ffi::OsString::from(
            Alphanumeric.sample_string(&mut rand::rng(), 16),
        ));
        std::fs::create_dir(&dir).expect("Could not create test temporary directory.");
        dir
    }

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
        let cert = cert.cache("/foo/bar".into(), &temp_dir())?;
        let config = cert.ssh_config()?;
        let mut reader = std::io::BufReader::new(config.as_bytes());
        let config = SshConfig::default().parse(&mut reader, ParseRule::STRICT)?;
        println!("{}", &config);
        assert_eq!(
            config.query("proj1.1.example").user,
            Some("foo.proj1".to_string())
        );
        assert_eq!(
            config.query("proj1.2.example").user,
            Some("foo.proj1".to_string())
        );
        assert_eq!(
            config.query("proj2.1.example").user,
            Some("foo.proj2".to_string())
        );
        assert!(config
            .get_hosts()
            .iter()
            .any(|h| h.intersects("proj2.2.example")));

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
                    "associations": {
                        "projects": {
                            "proj1": {
                                "name" : "Foo project",
                                "resources" : {
                                    "plat1": {
                                        "username": "foo.1",
                                        "certificate": certificate,
                                    },
                                    "plat2": {
                                        "username": "foo.2",
                                        "certificate": certificate,
                                    },
                                }
                            },
                            "proj2": {
                                "name" : "Bar project",
                                "resources" : {
                                    "plat1": {
                                        "username": "foo.1",
                                        "certificate": certificate,
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
        let cert = cert.cache("/foo/bar".into(), &temp_dir())?;
        let config = cert.ssh_config()?;
        let mut reader = std::io::BufReader::new(config.as_bytes());
        let config = SshConfig::default().parse(&mut reader, ParseRule::STRICT)?;
        assert_eq!(
            config.query("proj1.1.example").user,
            Some("foo.1".to_string())
        );
        assert_eq!(
            config.query("proj1.2.example").user,
            Some("foo.2".to_string())
        );
        assert_eq!(
            config.query("proj2.1.example").user,
            Some("foo.1".to_string())
        );
        assert!(config
            .get_hosts()
            .iter()
            .any(|h| h.intersects("proj2.2.example")));

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
                    "associations": {
                        "resources": {
                            "plat1": {
                                "username": "foo.1",
                                "certificate": certificate,
                            },
                            "plat2": {
                                "username": "foo.2",
                                "certificate": certificate,
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
        let cert = cert.cache("/foo/bar".into(), &temp_dir())?;
        let config = cert.ssh_config()?;
        let mut reader = std::io::BufReader::new(config.as_bytes());
        let config = SshConfig::default().parse(&mut reader, ParseRule::STRICT)?;
        assert_eq!(config.query("1.example").user, Some("foo.1".to_string()));
        assert_eq!(config.query("2.example").user, Some("foo.2".to_string()));

        Ok(())
    }
}
