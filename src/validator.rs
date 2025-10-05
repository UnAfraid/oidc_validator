use crate::config::Config;
use jsonwebtoken::{decode, decode_header, jwk, DecodingKey, TokenData, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

// --- Caching Infrastructure ---

#[derive(Clone, Deserialize)]
struct OidcWellKnown {
    jwks_uri: String,
}

static JWKS_URI_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
static JWKS_CACHE: OnceLock<Mutex<HashMap<String, Arc<jwk::JwkSet>>>> = OnceLock::new();

fn get_jwks_uri_cache() -> &'static Mutex<HashMap<String, String>> {
    JWKS_URI_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_jwks_cache() -> &'static Mutex<HashMap<String, Arc<jwk::JwkSet>>> {
    JWKS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

// --- OIDC Discovery & JWKS Fetching ---

fn discover_jwks_uri(issuer: &str) -> Result<String, String> {
    // Check cache first
    {
        let cache = get_jwks_uri_cache().lock().unwrap();
        if let Some(uri) = cache.get(issuer) {
            return Ok(uri.clone());
        }
    }

    // If not in cache, perform discovery
    pgrx::info!("Performing OIDC discovery for issuer: {}", issuer);
    let wellknown_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );

    let resp = reqwest::blocking::get(&wellknown_url)
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

    // Store in cache
    {
        let mut cache = get_jwks_uri_cache().lock().unwrap();
        cache.insert(issuer.to_string(), jwks_uri.clone());
    }

    Ok(jwks_uri)
}

fn get_jwks(jwks_uri: &str) -> Result<Arc<jwk::JwkSet>, String> {
    // Check cache first
    {
        let cache = get_jwks_cache().lock().unwrap();
        if let Some(jwks) = cache.get(jwks_uri) {
            return Ok(jwks.clone());
        }
    }

    // If not in cache, fetch JWKS
    pgrx::info!("Fetching JWKS from: {}", jwks_uri);
    let resp = reqwest::blocking::get(jwks_uri).map_err(|e| format!("Failed to fetch JWKS: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Failed to fetch JWKS: status {}", resp.status()));
    }

    let jwks: jwk::JwkSet = resp
        .json()
        .map_err(|e| format!("Failed to parse JWKS: {}", e))?;
    let jwks_arc = Arc::new(jwks);

    // Store in cache
    {
        let mut cache = get_jwks_cache().lock().unwrap();
        cache.insert(jwks_uri.to_string(), jwks_arc.clone());
    }

    Ok(jwks_arc)
}

// --- JWT Validation ---

#[derive(Debug, Deserialize, Clone)]
struct Claims {
    sub: String,
}

fn validate_jwt(token: &str, config: &Config) -> Result<String, String> {
    let issuer = config
        .oauth_issuer
        .as_ref()
        .ok_or("OAuth issuer not configured")?;
    let jwks_uri = discover_jwks_uri(issuer)?;

    let header = decode_header(token).map_err(|e| format!("Invalid JWT header: {}", e))?;
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

    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| format!("Failed to create decoding key from JWK: {}", e))?;

    let token_data: TokenData<Claims> = decode(token, &decoding_key, &validation)
        .map_err(|e| format!("JWT validation failed: {}", e))?;

    Ok(token_data.claims.sub)
}

// --- Main Validation Logic ---

pub fn safe_validate(config: &Config, token: &str, _role: &str) -> (bool, Option<String>) {
    // This validator only supports JWTs that can be validated client-side.
    if token.matches('.').count() != 2 {
        pgrx::warning!("Token does not appear to be a JWT. This validator only supports JWTs.");
        return (false, None);
    }

    match validate_jwt(token, config) {
        Ok(authn_id) => {
            pgrx::info!("Successfully validated token client-side as JWT");
            (true, Some(authn_id))
        }
        Err(e) => {
            pgrx::warning!("JWT validation failed: {}", e);
            (false, None)
        }
    }
}