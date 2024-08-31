use k8s_openapi::api::networking::v1::Ingress;
use kube::{
    api::{Api, ListParams},
    runtime::reflector::Lookup,
    Client, Error,
};
use tracing::info;

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
        let ingresses: Api<Ingress> = Api::all(client);
        let lp = ListParams::default();
        let ingress_list = ingresses.list(&lp).await?;

        let mut list: Vec<Self> = vec![];

        ingress_list
            .items
            .iter()
            .filter(|ingress| {
                ingress
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|annotations| {
                        annotations.get("oidc.ingress.kubernetes.io/oidc-forward-auth-enabled")
                    })
                    .is_some()
            })
            .for_each(|ingress| {
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

                list.push(K8sIngressProvider {
                    hostnames,
                    client_id: annotations
                        .get("oidc.ingress.kubernetes.io/oidc-client-id")
                        .unwrap()
                        .to_owned(),
                    client_secret: annotations
                        .get("oidc.ingress.kubernetes.io/oidc-client-secret")
                        .unwrap()
                        .to_owned(),
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
            });

        info!("{:#?}", list);

        return Ok(list);
    }
}
