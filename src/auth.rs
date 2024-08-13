// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use oauth2::reqwest::http_client;
use oauth2::{
    basic::BasicClient, AuthType, AuthUrl, ClientId, DeviceAuthorizationUrl, Scope,
    StandardDeviceAuthorizationResponse, TokenUrl,
};
use oauth2::{AccessToken, TokenResponse as _};
use qrcode::{render::unicode, QrCode};
use url::Url;

use crate::cache;

/// Given an OAuth `client_id` and URL, authenticate with the device code workflow
pub fn get_keycloak_token<P: AsRef<std::path::Path>>(
    client_id: &String,
    issuer_url: &Url,
    open_webpage: bool,
    show_qr: bool,
    token_cache_path: P,
) -> Result<AccessToken> {
    let client_id = ClientId::new(client_id.to_string());
    let client_secret = None;

    // TODO get these from https://{keycloak}/realms/{realm}/.well-known/openid-configuration
    let auth_url =
        AuthUrl::from_url(format!("{issuer_url}/protocol/openid-connect/auth/device").parse()?);
    let token_url =
        TokenUrl::from_url(format!("{issuer_url}/protocol/openid-connect/token").parse()?);
    let device_auth_url = DeviceAuthorizationUrl::from_url(
        format!("{issuer_url}/protocol/openid-connect/auth/device").parse()?,
    );

    // Set up the config for the Keycloak OAuth2 process.
    let device_client = BasicClient::new(client_id, client_secret, auth_url, Some(token_url))
        .set_device_authorization_url(device_auth_url)
        .set_auth_type(AuthType::RequestBody);

    // Request the set of codes from the Device Authorization endpoint.
    let details: StandardDeviceAuthorizationResponse = device_client
        .exchange_device_code()
        .context("Cound not exchange device code.")?
        .add_scope(Scope::new("openid".to_string()))
        .request(http_client)
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
        let qr = QrCode::new(verification_uri_complete)?
            .render::<unicode::Dense1x2>()
            .light_color(unicode::Dense1x2::Light)
            .dark_color(unicode::Dense1x2::Dark)
            .build();
        println!("Or scan this QR code:\n{qr}");
    }

    // Now poll for the token
    let token = device_client
        .exchange_device_access_token(&details)
        .request(http_client, std::thread::sleep, None)
        .context("Could not get token from KeyCloak.")?;

    cache::write_file(token_cache_path, token.access_token().secret())?;
    Ok(token.access_token().clone())
}
