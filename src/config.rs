use std::env::var;

#[derive(Default)]
pub struct Config {
    pub oauth_issuer: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_audience: Option<String>,
}

impl Config {
    pub fn new_from_env() -> Self {
        Config {
            oauth_issuer: var("POSTGRES_OIDC_ISSUER").ok(),
            oauth_client_id: var("POSTGRES_OIDC_CLIENT_ID").ok(),
            oauth_audience: var("POSTGRES_OIDC_AUDIENCE").ok(),
        }
    }
}
