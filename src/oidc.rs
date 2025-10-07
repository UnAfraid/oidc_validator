use crate::config::Config;
use jsonwebtoken::{decode, decode_header, jwk, DecodingKey, TokenData, Validation};
use serde::Deserialize;
use std::sync::{Arc};
use reqwest::Url;

const WELL_KNOWN_ENDPOINT: &'static str = ".well-known/openid-configuration";

#[derive(Clone, Deserialize)]
struct OidcWellKnown {
    jwks_uri: String,
}

fn discover_jwks_uri(issuer: &str) -> Result<String, String> {
    let issuer_url = Url::parse(issuer)
        .map_err(|e| format!("Failed to parse issuer url: {:?}", e))?;
    let well_known_url = issuer_url.join(WELL_KNOWN_ENDPOINT)
        .map_err(|e| format!("Failed to join issuer url with well known url: {:?}", e))?;

    pgrx::info!("Performing OIDC discovery for issuer: {}", well_known_url.as_str());

    let resp = reqwest::blocking::get(well_known_url)
        .map_err(|e| format!("Failed to fetch OIDC well-known config: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Failed to fetch OIDC well-known config: status {}",
            resp.status()
        ));
    }

    let config: OidcWellKnown = resp
        .json()
        .map_err(|e| format!("Failed to parse OIDC well-known config: {}", e))?;
    let jwks_uri = config.jwks_uri;

    Ok(jwks_uri)
}

fn get_jwks(jwks_uri: &str) -> Result<Arc<jwk::JwkSet>, String> {
    pgrx::info!("Fetching JWKS from: {}", jwks_uri);
    let resp = reqwest::blocking::get(jwks_uri)
        .map_err(|e| format!("Failed to fetch JWKS: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("Failed to fetch JWKS: status {}", resp.status()));
    }

    let jwks: jwk::JwkSet = resp
        .json()
        .map_err(|e| format!("Failed to parse JWKS: {}", e))?;
    let jwks_arc = Arc::new(jwks);

    Ok(jwks_arc)
}

#[derive(Debug, Deserialize, Clone)]
struct Claims {
    sub: String,
}

pub fn validate_jwt(token: &str, config: &Config) -> Result<String, String> {
    let issuer = config
        .oauth_issuer
        .as_ref()
        .ok_or("OAuth issuer not configured")?;
    let jwks_uri = discover_jwks_uri(issuer)?;

    let header = decode_header(token)
        .map_err(|e| format!("Invalid JWT header: {}", e))?;
    let kid = header.kid.ok_or("JWT missing 'kid' in header")?;

    let jwks = get_jwks(&jwks_uri)?;
    let jwk = jwks.find(&kid).ok_or(format!("JWK not found for kid: {}", kid))?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer]);

    if let Some(audience) = &config.oauth_audience {
        validation.set_audience(&[audience.as_str()]);
    } else {
        validation.validate_aud = false;
    }

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| format!("Failed to create decoding key from JWK: {}", e))?;

    let token_data: TokenData<Claims> = decode(token, &decoding_key, &validation)
        .map_err(|e| format!("JWT validation failed: {}", e))?;

    Ok(token_data.claims.sub)
}