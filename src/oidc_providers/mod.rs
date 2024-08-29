use std::{collections::HashMap, env};

use jsonwebtoken::jwk::JwkSet;
use openidconnect::core::CoreProviderMetadata;
use openidconnect::reqwest::http_client;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, Scope};
use tracing::{debug, info, warn};

#[derive(Clone, Debug)]
pub struct OIDCProvider {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub issuer_url: IssuerUrl,
    pub scopes: Vec<Scope>,
    pub jwks: JwkSet,
    pub audience: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct OIDCProviders {
    providers: HashMap<String, OIDCProvider>,
}

impl OIDCProviders {
    pub fn new() -> Self {
        let mut providers = Self {
            providers: HashMap::new(),
        };

        providers.load_from_env();
        providers.load_from_k8s();

        providers
    }

    fn load_from_env(&mut self) -> () {
        info!("Starting to initialize OIDC providers.");

        for i in 0u32.. {
            let hostname =
                env::var(&format!("OIDC_PROVIDER_{}_HOSTNAME", i)).map(|s| s.to_lowercase());

            let issuer_url = env::var(&format!("OIDC_PROVIDER_{}_ISSUER_URL", i));
            let client_id = env::var(&format!("OIDC_PROVIDER_{}_CLIENT_ID", i));
            let client_secret = env::var(&format!("OIDC_PROVIDER_{}_CLIENT_SECRET", i));
            let scopes = env::var(&format!("OIDC_PROVIDER_{}_SCOPES", i));
            let audience = env::var(&format!("OIDC_PROVIDER_{}_AUDIENCE", i));

            if hostname.clone().is_ok_and(|h| !h.is_empty())
                && issuer_url.clone().is_ok_and(|h| !h.is_empty())
                || client_id.clone().is_ok_and(|h| !h.is_empty())
                || client_secret.clone().is_ok_and(|h| !h.is_empty())
                || audience.clone().is_ok_and(|h| !h.is_empty())
            {
                debug!("OIDC provider init: Environment variable set with counter {} is incomplete. Stopping here.", i);
                break;
            }

            let provider_metadata = CoreProviderMetadata::discover(
                &IssuerUrl::new(issuer_url.clone().unwrap().to_owned())
                    .expect("Invalid issuer URL"),
                http_client,
            )
            .unwrap();

            let jwks: JwkSet = reqwest::blocking::Client::builder()
                .use_rustls_tls()
                .build()
                .unwrap()
                .get(&provider_metadata.jwks_uri().url().to_string())
                .send()
                .unwrap()
                .json()
                .unwrap();

            let oidc_provider = OIDCProvider {
                client_id: ClientId::new(client_id.unwrap()),
                client_secret: ClientSecret::new(client_secret.unwrap()),
                issuer_url: IssuerUrl::new(issuer_url.clone().unwrap().to_owned())
                    .expect("Invalid issuer URL"),
                scopes: scopes
                    .unwrap_or_else(|_| "".to_string())
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| Scope::new(s.trim().to_string()))
                    .collect(),
                audience: audience.unwrap().split(',').map(String::from).collect(),
                jwks,
            };

            debug!("OIDC provider details: {:?}", &oidc_provider);

            self.providers
                .insert(hostname.clone().unwrap().to_owned(), oidc_provider);

            info!(
                "Added OIDC provider: {} -> {}",
                &hostname.unwrap(),
                &issuer_url.unwrap()
            );
        }

        if self.providers.len() == 0 {
            warn!("No OIDC providers initialized. Please check environment variables.")
        } else {
            info!("Initialized {} OIDC providers.", self.providers.len());
        }
    }

    fn load_from_k8s(&mut self) -> () {}

    pub fn find_by_hostname(&self, hostname: &str) -> Option<&OIDCProvider> {
        self.providers.get(&hostname.to_lowercase())
    }
}
