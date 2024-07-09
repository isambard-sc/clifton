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
use serde::Deserialize;
use url::Url;

#[derive(Deserialize)]
struct Token {
    token: String,
}

/// Given an OAuth `client_id` and URL, authenticate with the device code workflow
pub fn get_keycloak_token(
    client_id: &String,
    issuer_url: &Url,
    open_webpage: bool,
) -> Result<AccessToken> {
    let client_id = ClientId::new(client_id.to_string());
    let client_secret = None;

    let auth_url = AuthUrl::from_url(issuer_url.join("protocol/openid-connect/auth/device")?);
    let token_url = TokenUrl::from_url(issuer_url.join("protocol/openid-connect/token")?);
    let device_auth_url =
        DeviceAuthorizationUrl::from_url(issuer_url.join("protocol/openid-connect/auth/device")?);

    // Set up the config for the Keycloak OAuth2 process.
    let device_client = BasicClient::new(client_id, client_secret, auth_url, Some(token_url))
        .set_device_authorization_url(device_auth_url)
        .set_auth_type(AuthType::RequestBody);

    // Request the set of codes from the Device Authorization endpoint.
    let details: StandardDeviceAuthorizationResponse = device_client
        .exchange_device_code()
        .context("Exchanging device code")?
        .add_scope(Scope::new("openid".to_string()))
        .request(http_client)
        .context("Failed to request codes from device auth endpoint")?;

    // Display the URL and user-code.
    let verification_uri_complete = details
        .verification_uri_complete()
        .context("Did not receive complete verification URI from server.")?
        .secret();
    if open_webpage {
        webbrowser::open(verification_uri_complete)
            .ok()
            .context("Opening web browser")?;
    }
    println!(
        "Open this URL in your browser:\n{}",
        &verification_uri_complete
    );
    let qr = QrCode::new(verification_uri_complete)?
        .render::<unicode::Dense1x2>()
        .light_color(unicode::Dense1x2::Light)
        .dark_color(unicode::Dense1x2::Dark)
        .build();
    println!("Or scan this QR code:\n{}", qr);

    // Now poll for the token
    let token = device_client
        .exchange_device_access_token(&details)
        .request(http_client, std::thread::sleep, None)
        .context("Getting token from KeyCloak")?;

    Ok(token.access_token().clone())
}

/// Using the token from KeyCloak, ask Waldur for an API token
pub fn get_waldur_token(waldur_api_url: &Url, kc_token: AccessToken) -> Result<String> {
    let url = format!("{}api-auth/keycloak", waldur_api_url);
    let r = reqwest::blocking::Client::new()
        .get(url)
        .header("Accept", "application/json")
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", kc_token.secret()),
        )
        .send()?;
    Ok(r.json::<Token>()?.token)
}
