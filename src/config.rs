use std::collections::HashMap;

#[derive(Default)]
pub struct Config {
    pub oauth_issuer: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,
    pub oauth_scope: Option<String>,
    pub oauth_audience: Option<String>,
}

impl Config {
    pub fn new_from_conn_params(conn_params: &HashMap<String, String>) -> Result<Self, String> {
        Ok(Config {
            oauth_issuer: conn_params.get("issuer").cloned().or_else(|| std::env::var("PGOAUTH_ISSUER").ok()),
            oauth_client_id: conn_params.get("client_id").cloned().or_else(|| std::env::var("PGOAUTH_CLIENT_ID").ok()),
            oauth_client_secret: conn_params.get("client_secret").cloned().or_else(|| std::env::var("PGOAUTH_CLIENT_SECRET").ok()),
            oauth_scope: conn_params.get("scope").cloned().or_else(|| std::env::var("PGOAUTH_SCOPE").ok()),
            oauth_audience: conn_params.get("audience").cloned().or_else(|| std::env::var("PGOAUTH_AUDIENCE").ok()),
        })
    }
}
