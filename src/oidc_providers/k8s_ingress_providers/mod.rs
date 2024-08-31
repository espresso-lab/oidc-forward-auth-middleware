use k8s_openapi::api::{core::v1::Secret, networking::v1::Ingress};
use kube::{
    api::{Api, ListParams},
    runtime::reflector::Lookup,
    Client, Error,
};
use tracing::{error, info};

#[derive(Clone, Debug)]
pub struct K8sIngressProvider {
    pub hostnames: Vec<String>,
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,
    pub scopes: String,
    pub audience: String,
}

impl K8sIngressProvider {
    pub async fn discover_all() -> Result<Vec<Self>, Error> {
        let client = Client::try_default().await?;
        let ingresses: Api<Ingress> = Api::all(client.to_owned());
        let lp = ListParams::default();

        let mut return_list: Vec<Self> = vec![];

        let ingress_res = ingresses.list(&lp).await?;

        let ingress_list = ingress_res.items.iter().filter(|ingress| {
            ingress
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| {
                    annotations.get("oidc.ingress.kubernetes.io/oidc-forward-auth-enabled")
                })
                .is_some()
        });

        for ingress in ingress_list.into_iter() {
            info!(
                "K8s Ingress: {} in namespace {}",
                ingress.name().unwrap(),
                ingress.namespace().unwrap()
            );

            let annotations = ingress.metadata.annotations.as_ref().unwrap();

            let hostnames = ingress
                .spec
                .as_ref()
                .unwrap()
                .rules
                .as_ref()
                .unwrap()
                .iter()
                .map(|ingress_host| ingress_host.host.clone().unwrap())
                .collect();

            // TODO: Get client-secret from k8s secret
            let client_id: String;
            let client_secret: String;
            let oidc_secret = annotations.get("oidc.ingress.kubernetes.io/oidc-existing-secret");

            if oidc_secret.is_some() {
                info!(
                    "Fetching secret {} in namespace {}.",
                    &oidc_secret.unwrap(),
                    &ingress.namespace().unwrap().to_string()
                );

                let secret: Secret =
                    Api::namespaced(client.to_owned(), &ingress.namespace().unwrap().to_string())
                        .get(oidc_secret.unwrap())
                        .await?;

                if let Some(data) = secret.data {
                    client_id =
                        String::from_utf8(data.get("client_id").unwrap().0.to_owned()).unwrap();
                    client_secret =
                        String::from_utf8(data.get("client_secret").unwrap().0.to_owned()).unwrap();

                    info!("Found client_id {} and {}.", &client_id, &client_secret);
                } else {
                    error!("Invalid oidc secret");
                    break;
                }
            } else {
                client_id = annotations
                    .get("oidc.ingress.kubernetes.io/oidc-client-id")
                    .unwrap()
                    .to_owned();

                client_secret = annotations
                    .get("oidc.ingress.kubernetes.io/oidc-client-secret")
                    .unwrap()
                    .to_owned();
            }

            return_list.push(K8sIngressProvider {
                hostnames,
                client_id,
                client_secret,
                issuer_url: annotations
                    .get("oidc.ingress.kubernetes.io/oidc-issuer-url")
                    .unwrap()
                    .to_owned(),
                scopes: annotations
                    .get("oidc.ingress.kubernetes.io/oidc-scopes")
                    .unwrap()
                    .to_owned(),
                audience: annotations
                    .get("oidc.ingress.kubernetes.io/oidc-audience")
                    .unwrap()
                    .to_owned(),
            });
        }

        info!("{:#?}", return_list);

        return Ok(return_list);
    }
}
