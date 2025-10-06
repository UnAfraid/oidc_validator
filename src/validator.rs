use crate::config::Config;
use crate::oidc::validate_jwt;

pub fn safe_validate(config: &Config, token: &str, _role: &str) -> (bool, Option<String>) {
    if token.matches('.').count() != 2 {
        pgrx::warning!("Token does not appear to be a JWT. This validator only supports JWTs.");
        return (false, None);
    }

    match validate_jwt(token, config) {
        Ok(subject) => {
            pgrx::info!("Successfully validated JWT token for: {}", subject);
            (true, Some(subject))
        }
        Err(e) => {
            pgrx::warning!("JWT validation failed: {}", e);
            (false, None)
        }
    }
}