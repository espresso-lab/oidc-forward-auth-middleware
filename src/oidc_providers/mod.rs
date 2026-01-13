mod k8s_ingress_providers;

use std::{collections::HashMap, env, sync::OnceLock};

use jsonwebtoken::jwk::JwkSet;
use k8s_ingress_providers::K8sIngressProvider;
use kube::Error;
use openidconnect::core::CoreProviderMetadata;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, Scope};
use tracing::{debug, info, warn};

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

pub fn get_http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .use_rustls_tls()
            .build()
            .expect("Failed to build HTTP client")
    })
}

#[derive(Clone, Debug)]
pub struct OIDCProvider {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub issuer_url: IssuerUrl,
    pub scopes: Vec<Scope>,
    pub jwks: JwkSet,
    pub audience: Vec<String>,
}

impl OIDCProvider {
    pub async fn new(
        issuer_url: String,
        client_id: String,
        client_secret: String,
        scopes: String,
        audience: String,
    ) -> Self {
        let http_client = get_http_client();
        let issuer = IssuerUrl::new(issuer_url).expect("Invalid issuer URL");

        let provider_metadata = CoreProviderMetadata::discover_async(issuer.clone(), http_client)
            .await
            .unwrap();

        let jwks: JwkSet = http_client
            .get(provider_metadata.jwks_uri().url().as_str())
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        OIDCProvider {
            client_id: ClientId::new(client_id),
            client_secret: ClientSecret::new(client_secret),
            issuer_url: issuer,
            scopes: scopes
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| Scope::new(s.trim().to_string()))
                .collect(),
            audience: audience.split(',').map(String::from).collect(),
            jwks,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OIDCProviders {
    providers: HashMap<String, OIDCProvider>,
}

impl OIDCProviders {
    pub async fn new() -> Self {
        let mut providers = Self {
            providers: HashMap::new(),
        };

        let () = providers.load_from_env().await;
        let _ = providers.load_from_k8s().await;

        providers
    }

    async fn load_from_env(&mut self) {
        info!("Starting to initialize OIDC providers from ENV.");

        for i in 0u32.. {
            let hostname =
                env::var(format!("OIDC_PROVIDER_{i}_HOSTNAME")).map(|s| s.to_lowercase());
            let issuer_url = env::var(format!("OIDC_PROVIDER_{i}_ISSUER_URL"));
            let client_id = env::var(format!("OIDC_PROVIDER_{i}_CLIENT_ID"));
            let client_secret = env::var(format!("OIDC_PROVIDER_{i}_CLIENT_SECRET"));
            let scopes = env::var(format!("OIDC_PROVIDER_{i}_SCOPES"));
            let audience = env::var(format!("OIDC_PROVIDER_{i}_AUDIENCE"));

            let (
                Ok(hostname),
                Ok(issuer_url),
                Ok(client_id),
                Ok(client_secret),
                Ok(scopes),
                Ok(audience),
            ) = (
                hostname,
                issuer_url,
                client_id,
                client_secret,
                scopes,
                audience,
            )
            else {
                debug!("OIDC provider init: Environment variable set with counter {i} is incomplete. Stopping here.");
                break;
            };

            let oidc_provider = OIDCProvider::new(
                issuer_url.clone(),
                client_id,
                client_secret,
                scopes,
                audience,
            )
            .await;

            debug!("OIDC provider details: {:?}", &oidc_provider);
            info!("Added OIDC provider: {} -> {}", &hostname, &issuer_url);

            self.providers.insert(hostname, oidc_provider);
        }

        if self.providers.is_empty() {
            warn!("No OIDC providers initialized. Please check environment variables.");
        } else {
            info!("Initialized {} OIDC providers.", self.providers.len());
        }
    }

    async fn load_from_k8s(&mut self) -> Result<(), Error> {
        // Exit if this is not running in K8s
        if env::var("KUBERNETES_SERVICE_HOST").is_err() {
            return Ok(());
        }

        info!("Starting to initialize OIDC providers from K8s.");

        let k8s_providers = K8sIngressProvider::discover_all().await?;

        for k8s_provider in &k8s_providers {
            let oidc_provider = OIDCProvider::new(
                k8s_provider.issuer_url.clone(),
                k8s_provider.client_id.clone(),
                k8s_provider.client_secret.clone(),
                k8s_provider.scopes.clone(),
                k8s_provider.audience.clone(),
            )
            .await;

            info!("K8s OIDC provider details: {:?}", &oidc_provider);

            k8s_provider.hostnames.iter().for_each(|hostname| {
                self.providers
                    .insert(hostname.to_lowercase(), oidc_provider.clone());
            });
        }

        Ok(())
    }

    pub fn find_by_hostname(&self, hostname: &str) -> Option<&OIDCProvider> {
        self.providers.get(&hostname.to_lowercase())
    }
}
