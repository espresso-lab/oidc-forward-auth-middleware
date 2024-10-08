mod k8s_ingress_providers;

use std::{collections::HashMap, env};

use jsonwebtoken::jwk::JwkSet;
use k8s_ingress_providers::K8sIngressProvider;
use kube::Error;
use openidconnect::core::CoreProviderMetadata;
use openidconnect::reqwest::async_http_client;
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

impl OIDCProvider {
    pub async fn new(
        issuer_url: String,
        client_id: String,
        client_secret: String,
        scopes: String,
        audience: String,
    ) -> Self {
        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url.to_owned()).expect("Invalid issuer URL"),
            async_http_client,
        )
        .await
        .unwrap();

        let jwks: JwkSet = reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .unwrap()
            .get(&provider_metadata.jwks_uri().url().to_string())
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        OIDCProvider {
            client_id: ClientId::new(client_id),
            client_secret: ClientSecret::new(client_secret),
            issuer_url: IssuerUrl::new(issuer_url.to_owned()).expect("Invalid issuer URL"),
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

        let _ = providers.load_from_env().await;
        let _ = providers.load_from_k8s().await;

        providers
    }

    async fn load_from_env(&mut self) -> () {
        info!("Starting to initialize OIDC providers from ENV.");

        for i in 0u32.. {
            let hostname =
                env::var(&format!("OIDC_PROVIDER_{}_HOSTNAME", i)).map(|s| s.to_lowercase());

            let issuer_url = env::var(&format!("OIDC_PROVIDER_{}_ISSUER_URL", i));
            let client_id = env::var(&format!("OIDC_PROVIDER_{}_CLIENT_ID", i));
            let client_secret = env::var(&format!("OIDC_PROVIDER_{}_CLIENT_SECRET", i));
            let scopes = env::var(&format!("OIDC_PROVIDER_{}_SCOPES", i));
            let audience = env::var(&format!("OIDC_PROVIDER_{}_AUDIENCE", i));

            if hostname.clone().is_err() && issuer_url.clone().is_err()
                || client_id.clone().is_err()
                || client_secret.clone().is_err()
                || audience.clone().is_err()
            {
                debug!("OIDC provider init: Environment variable set with counter {} is incomplete. Stopping here.", i);
                break;
            }

            let oidc_provider = OIDCProvider::new(
                issuer_url.clone().unwrap(),
                client_id.unwrap(),
                client_secret.unwrap(),
                scopes.unwrap(),
                audience.unwrap(),
            )
            .await;

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

    async fn load_from_k8s(&mut self) -> Result<(), Error> {
        // Exit if this is not running in K8s
        if env::var("KUBERNETES_SERVICE_HOST").is_err() {
            return Ok(());
        } else {
            info!("Starting to initialize OIDC providers from K8s.");
        }

        let k8s_providers = K8sIngressProvider::discover_all().await?;

        for k8s_provider in k8s_providers.iter() {
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
                    .insert(hostname.to_lowercase().to_owned(), oidc_provider.clone());
            });
        }

        return Ok(());
    }

    pub fn find_by_hostname(&self, hostname: &str) -> Option<&OIDCProvider> {
        self.providers.get(&hostname.to_lowercase())
    }
}
