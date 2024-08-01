// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod,
    CoreDeviceAuthorizationResponse, CoreGrantType, CoreJsonWebKey, CoreJsonWebKeyType,
    CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::reqwest::http_client;
use openidconnect::{
    AccessToken, AdditionalProviderMetadata, AuthType, ClientId, DeviceAuthorizationUrl, IssuerUrl,
    OAuth2TokenResponse as _, ProviderMetadata, Scope,
};
use qrcode::{render::unicode, QrCode};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{cache, config};

#[derive(Deserialize)]
struct Token {
    token: String,
}

// Obtain the device_authorization_url from the OIDC metadata provider.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct DeviceEndpointProviderMetadata {
    device_authorization_endpoint: DeviceAuthorizationUrl,
}
impl AdditionalProviderMetadata for DeviceEndpointProviderMetadata {}
type DeviceProviderMetadata = ProviderMetadata<
    DeviceEndpointProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

/// Given an OAuth `client_id` and URL, authenticate with the device code workflow
pub fn get_keycloak_token(
    client_id: &String,
    issuer_url: &Url,
    open_webpage: bool,
) -> Result<AccessToken> {
    let issuer_url = IssuerUrl::from_url(issuer_url.clone());
    let client_id = ClientId::new(client_id.to_string());
    let client_secret = None;

    let provider_metadata = DeviceProviderMetadata::discover(&issuer_url, http_client)
        .context("Cannot discover OIDC metadata.")?;

    let device_auth_url = provider_metadata
        .additional_metadata()
        .device_authorization_endpoint
        .clone();

    let device_client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, client_secret)
            .set_device_authorization_uri(device_auth_url)
            .set_auth_type(AuthType::RequestBody);

    // Request the set of codes from the Device Authorization endpoint.
    let details: CoreDeviceAuthorizationResponse = device_client
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
    let qr = QrCode::new(verification_uri_complete)?
        .render::<unicode::Dense1x2>()
        .light_color(unicode::Dense1x2::Light)
        .dark_color(unicode::Dense1x2::Dark)
        .build();
    println!("Or scan this QR code:\n{qr}");

    // Now poll for the token
    let token = device_client
        .exchange_device_access_token(&details)
        .request(http_client, std::thread::sleep, None)
        .context("Could not get token from KeyCloak.")?;

    Ok(token.access_token().clone())
}

/// Using the token from KeyCloak, ask Waldur for an API token
pub fn get_waldur_token(waldur_api_url: &Url, kc_token: &AccessToken) -> Result<String> {
    let url = format!("{waldur_api_url}api-auth/keycloak/");
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

/// Do the full authentication pathway with OAuth and Waldur to get
/// the Waldur API token. Finally, cache it.
pub fn get_api_key<P: AsRef<std::path::Path>>(
    config: &config::Config,
    key_cache_path: P,
    open_browser: bool,
) -> Result<String, anyhow::Error> {
    let kc_token = get_keycloak_token(&config.client_id, &config.keycloak_url, open_browser)
        .context("Could not get OAuth token.")?;
    let api_key = get_waldur_token(&config.waldur_api_url, &kc_token)
        .context("Could not get Waldur API token.")?;
    cache::write_file(key_cache_path, api_key.as_bytes())?;
    Ok(api_key)
}
