// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use chrono::TimeDelta;
use oauth2::{
    basic::BasicClient, AuthType, AuthUrl, ClientId, DeviceAuthorizationUrl, Scope,
    StandardDeviceAuthorizationResponse, TokenUrl,
};
use oauth2::{AccessToken, TokenResponse as _};
use qrcode::{render::unicode, QrCode};
use url::Url;

use crate::cache;
use crate::config;
use crate::get_cert;
use crate::print_available_aliases;
use crate::ssh_config_write;
use crate::AssociationsCache;
use crate::CaOidcResponse;
use crate::CertificateConfigCache;

/// Given an OAuth `client_id` and URL, authenticate with the device code workflow
fn get_access_token(
    client_id: &String,
    issuer_url: &Url,
    open_webpage: bool,
    show_qr: bool,
) -> Result<AccessToken> {
    // let http_client = reqwest::blocking::Client::new();
    let http_client = oauth2::reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Could not build HTTP client for authorisation.")?;

    let client_id = ClientId::new(client_id.to_string());

    // TODO get these from https://{provider}/realms/{realm}/.well-known/openid-configuration
    let auth_url =
        AuthUrl::from_url(format!("{issuer_url}/protocol/openid-connect/auth/device").parse()?);
    let token_url =
        TokenUrl::from_url(format!("{issuer_url}/protocol/openid-connect/token").parse()?);
    let device_auth_url = DeviceAuthorizationUrl::from_url(
        format!("{issuer_url}/protocol/openid-connect/auth/device").parse()?,
    );
    // Set up the config for the OIDC process.
    let device_client = BasicClient::new(client_id)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_device_authorization_url(device_auth_url)
        .set_auth_type(AuthType::RequestBody);

    // Request the set of codes from the Device Authorization endpoint.
    let details: StandardDeviceAuthorizationResponse = device_client
        .exchange_device_code()
        .add_scope(Scope::new("openid".to_string()))
        .request(&http_client)
        .context("Failed to request codes from device auth endpoint.")?;

    // Display the URL and user-code.
    let verification_uri_complete = details
        .verification_uri_complete()
        .context("Did not receive complete verification URI from server.")?
        .secret();
    if open_webpage {
        if let Err(e) = webbrowser::open(verification_uri_complete) {
            eprintln!("Could not launch web browser: {e:#}");
        }
    }
    println!("Open this URL in your browser:\n{verification_uri_complete}");
    if show_qr {
        let qr_code_url = Url::parse_with_params(verification_uri_complete, &[("qr", "1")])?;
        let qr = QrCode::new(qr_code_url.as_str())?
            .render::<unicode::Dense1x2>()
            .light_color(unicode::Dense1x2::Light)
            .dark_color(unicode::Dense1x2::Dark)
            .build();
        println!("Or scan this QR code:\n{qr}");
    }

    // Now poll for the token
    let token = device_client
        .exchange_device_access_token(&details)
        .request(&http_client, std::thread::sleep, None)
        .context("Could not get token from identity provider.")?;

    Ok(token.access_token().clone())
}

pub fn auth(
    config: config::Config,
    cert_details_file_name: String,
    identity: &Option<std::path::PathBuf>,
    open_browser: &Option<bool>,
    show_qr: &Option<bool>,
    write_config: &Option<bool>,
    passive: &Option<bool>,
) -> Result<(), anyhow::Error> {
    let green = anstyle::Style::new()
        .fg_color(Some(anstyle::AnsiColor::Green.into()))
        .bold();

    if passive.unwrap_or(config.passive) {
        if let Ok(cache_string) = cache::read_file(&cert_details_file_name) {
            let cert_config_cache: CertificateConfigCache = serde_json::from_str(&cache_string)?;
            let first_expiry = cert_config_cache.first_expiry();

            if let Some(first_expiry) = first_expiry {
                type Tz = chrono::offset::Utc; // TODO This is UNIX time, not UTC
                let valid_before: chrono::DateTime<Tz> = first_expiry.into();
                if (valid_before - Tz::now()) >= TimeDelta::zero() {
                    match &cert_config_cache.associations {
                        AssociationsCache::Projects(projects) => match projects.len() {
                            0 => {
                                anyhow::bail!("No currently valid projects.")
                            }
                            _ => {
                                let project_name_list = projects
                                    .iter()
                                    .map(|(p_id, p)| match p.name.as_str() {
                                        "" => format!("- {}", &p_id),
                                        name => format!(" - {} ({})", &p_id, name),
                                    })
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                println!(
                                    "{green}Valid certificates found for {} on projects{green:#}:\n{project_name_list}",
                                    &cert_config_cache.user
                                );
                            }
                        },
                        AssociationsCache::Resources(_resources) => println!(
                            "{green}Valid certificate found for {}.{green:#}",
                            &cert_config_cache.user
                        ),
                    }

                    println!(
                        "\nCall '{} auth --passive false' to force re-authentication.",
                        std::env::args().next().unwrap_or("clifton".to_string()),
                    );

                    return Ok(());
                }
            }
        }
    }

    let open_browser = open_browser.unwrap_or(config.open_browser);
    let show_qr = show_qr.unwrap_or(config.show_qr);
    let site_name = config.default_site;

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
                _ => anyhow::bail!(anyhow::anyhow!(e).context("Could not read SSH identity file.")),
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
    let oidc_details: CaOidcResponse = reqwest::blocking::get(format!("{}oidc", &site.ca_url))
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
        get_cert(&identity, &site.ca_url, token.secret()).context("Could not fetch certificate.")
    };
    let cert = match cert {
        Ok(cert) => cert,
        Err(e) => {
            cache::delete_file(cert_details_file_name).unwrap_or_default();
            anyhow::bail!(e)
        }
    };
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
                    .map(|(p_id, p)| match p.name.as_str() {
                        "" => format!("- {}", &p_id),
                        name => format!(" - {} ({})", &p_id, name),
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
    let first_expiry = cert_config_cache.first_expiry();
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

    Ok(())
}
