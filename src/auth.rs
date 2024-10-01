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

use crate::cache;

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
pub fn get_access_token<P: AsRef<std::path::Path>>(
    client_id: &String,
    issuer_url: &Url,
    open_webpage: bool,
    show_qr: bool,
    token_cache_path: P,
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
        .context("Could not get token from identity provider.")?;

    cache::write_file(token_cache_path, token.access_token().secret())?;
    Ok(token.access_token().clone())
}
