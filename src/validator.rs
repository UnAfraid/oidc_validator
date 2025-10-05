use crate::config::Config;
use serde::Deserialize;

#[derive(Deserialize)]
struct AuthentikIntrospectionResponse {
    active: bool,
    sub: Option<String>,
    scope: Option<String>,
    aud: Option<String>,
}

pub fn safe_validate(config: &Config, token: &str, role: &str) -> (bool, Option<String>) {
    // Extract OAuth parameters from config
    let introspection_url = match &config.oauth_issuer {
        Some(url) => format!("{}/introspect/", url.trim_end_matches('/')),
        None => {
            pgrx::warning!("OAuth issuer is not configured in Config");
            return (false, None);
        }
    };

    let client_id = match &config.oauth_client_id {
        Some(cid) => cid,
        None => {
            pgrx::warning!("OAuth client_id is not configured in Config");
            return (false, None);
        }
    };

    let client_secret = match &config.oauth_client_secret {
        Some(sec) => sec,
        None => {
            pgrx::warning!("OAuth client_secret is not configured in Config");
            return (false, None);
        }
    };

    // Perform introspection request
    let client = reqwest::blocking::Client::new();
    let params = [
        ("token", token),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];

    let resp = match client.post(&introspection_url).form(&params).send() {
        Ok(r) => r,
        Err(err) => {
            pgrx::warning!("Failed to contact introspection endpoint: {}", err);
            return (false, None);
        }
    };

    let data: AuthentikIntrospectionResponse = match resp.json() {
        Ok(d) => d,
        Err(err) => {
            pgrx::warning!("Failed to parse introspection response: {}", err);
            return (false, None);
        }
    };

    if !data.active {
        return (false, None);
    }

    // Validate audience if provided
    if let Some(aud) = &data.aud {
        if let Some(expected_aud) = &config.oauth_audience {
            if aud != expected_aud {
                pgrx::warning!("Token audience {} does not match expected {}", aud, expected_aud);
                return (false, None);
            }
        }
    }

    // Validate required scope
    if let Some(scopes) = &data.scope {
        if let Some(required_scope) = &config.oauth_scope {
            if !scopes.split_whitespace().any(|s| s == required_scope) {
                pgrx::warning!("Token missing required scope '{}'", required_scope);
                return (false, None);
            }
        }
    }

    let authn_id = data.sub.unwrap_or_else(|| role.to_string());
    (true, Some(authn_id))
}
