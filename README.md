# OIDC `ForwardAuth` middleware (for traefik)

[![GitHub tag](https://img.shields.io/github/tag/espresso-lab/oidc-forward-auth-middleware?include_prereleases=&sort=semver&color=blue)](https://github.com/espresso-lab/oidc-forward-auth-middleware/tags/)
[![License](https://img.shields.io/badge/License-MIT-blue)](#license)
[![Rust Report Card](https://rust-reportcard.xuri.me/badge/github.com/espresso-lab/oidc-forward-auth-middleware)](https://rust-reportcard.xuri.me/report/github.com/espresso-lab/oidc-forward-auth-middleware)

This container acts as a `ForwardAuth` middleware for the traefik ingress controller that provides OpenID Connect (OIDC) authorization.

## Features

- Blazing fast ⚡️ and written in Rust ⚙️
- Secure implementation 🔐
- Integration with traefik ingress controller
- Easy to deploy to a Kubernetes environment via Helm or to use it with Docker Compose
- Simple configuration via environment variables or Helm values

## Installation

### Installation via Helm

```
helm repo add espresso-lab https://espresso-lab.github.io/helm-charts

helm upgrade --install oidc-forward-auth-middleware espresso-lab/oidc-forward-auth-middleware --namespace=auth
```

## Usage

### Usage in Kubernetes / Helm

```yaml
config:
  sessionCookieName: x_forward_auth_session
  logLevel: info # debug, info, warn, error
  disableEnhancedSecurity: false # Enhanced security sets HTTP security headers and forces https

oidcProviders:
  - ingressHostname: example.com # Traefik ingress hostname you would like to protect
    issuerUrl: https://id.example.com/oauth/app1
    clientId: app1 # or use existingSecret
    clientSecret: mysecretpassword # or use existingSecret
    scopes: ["email", "profile"]
    #existingSecret: oidc-config # Provide a secret in the same namespace with fields clientId, clientSecret
    audience: ["app1"]
```

A secret could look like:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: oidc-config
  namespace: auth
type: Opaque
stringData:
  clientId: my-client-id
  clientSecret: my-client-secret
```

### Useage in Docker Compose

For the latest example have a look at the `docker-compose.yml` file.

```yaml
# Create middleware container
middleware:
  image: ghcr.io/espresso-lab/oidc-forward-auth-middleware:latest
  env_file:
    - .env.sample
  ports:
    - "3000:3000"

# Protect the whoami services
whoami:
  image: "traefik/whoami"
  container_name: "whoami"
  labels:
    - "traefik.enable=true"
    - "traefik.http.routers.whoami.rule=Host(`localhost`)"
    - "traefik.http.routers.whoami.entrypoints=web"
    - "traefik.http.routers.whoami.middlewares=test-auth@docker"
    # Apply the ForwardAuth middleware
    - "traefik.http.middlewares.test-auth.forwardauth.address=http://middleware:3000/verify"
    - "traefik.http.middlewares.test-auth.forwardauth.trustForwardHeader=true"
    - "traefik.http.middlewares.test-auth.forwardauth.authResponseHeaders=Set-Cookie,Location"
    - "traefik.http.middlewares.test-auth.forwardauth.authRequestHeaders=Accept,Cookie"
```

## Configuration

### Environment variables

#### General setting

| Environment variable      | Type    | Description                                                                                |
| ------------------------- | ------- | ------------------------------------------------------------------------------------------ |
| FORWARD_AUTH_COOKIE       | String  | Name of the browser cookie that stores the JWT session.                                    |
| RUST_LOG                  | String  | info, debug, error, warning                                                                |
| DISABLE_ENHANCED_SECURITY | Boolean | Default: `false`. Sets various security HTTP headers and redirects http requests to https. |

#### Per OIDC provider

Use `OIDC_PROVIDER_0_*` for the first provider, `OIDC_PROVIDER_1_*` for the second one and so on.

| Environment variable          | Type   | Description                                 |
| ----------------------------- | ------ | ------------------------------------------- |
| OIDC_PROVIDER_0_HOSTNAME      | String | Name of the hostname (traefik ingress host) |
| OIDC_PROVIDER_0_ISSUER_URL    | String | OIDC issuer url                             |
| OIDC_PROVIDER_0_CLIENT_ID     | String | OIDC client id                              |
| OIDC_PROVIDER_0_CLIENT_SECRET | String | OIDC client secret                          |
| OIDC_PROVIDER_0_SCOPES        | String | OIDC scopes (openid, email, ...)            |
| OIDC_PROVIDER_0_AUDIENCE      | String | OIDC audience                               |

## License

Released under [MIT](/LICENSE) by [@espresso-lab](https://github.com/espresso-lab).
