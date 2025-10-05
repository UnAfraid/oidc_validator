
#[derive(Default)]
pub struct Config {
    pub oauth_issuer: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,
    pub oauth_scope: Option<String>,
    pub oauth_audience: Option<String>,
}

impl Config {
    pub fn new_from_env() -> Self {
        Config {
            oauth_issuer: std::env::var("POSTGRES_OIDC_ISSUER").ok(),
            oauth_client_id: std::env::var("POSTGRES_OIDC_CLIENT_ID").ok(),
            oauth_client_secret: std::env::var("POSTGRES_OIDC_CLIENT_SECRET").ok(),
            oauth_scope: std::env::var("POSTGRES_OIDC_SCOPE").ok(),
            oauth_audience: std::env::var("POSTGRES_OIDC_AUDIENCE").ok(),
        }
    }
}
