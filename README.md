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

## Usage

### Usage in Kubernetes / Helm

Let's say you have a service called `app.example.com` you would like to protect with the OIDC middleware.
Your OIDC provider in the example is `id.example.com`.

First, install the `oidc-forward-auth-middleware` Helm chart:

```
helm repo add espresso-lab https://espresso-lab.github.io/helm-charts

helm upgrade --install oidc-forward-auth-middleware espresso-lab/oidc-forward-auth-middleware --namespace=auth
```

The Helm values could look like the following:

```yaml
# Example helm values of oidc-forward-auth-middleware

config:
  logLevel: info # debug, info, warn, error

oidcProviders:
  - ingressHostname: app.example.com # Traefik ingress hostname you would like to protect
    issuerUrl: https://id.example.com/oauth/app1
    clientId: app1
    clientSecret: mysecretpassword
    scopes: ["email", "profile"]
    # existingSecret: oidc-config # Provide a secret in the same namespace with fields clientId, clientSecret
    audience: ["app1"]
```

Last, enable it in the ingress controller of the service `app.example.com` you would like to protect:

```yaml
# Example helm values of service app.example.com
ingress:
  enabled: true
  hosts:
    - app.example.com
  ingressClassName: traefik
  annotations:
    # Enable middleware
    traefik.ingress.kubernetes.io/router.middlewares: kube-system-oidc-forward-auth-middleware@kubernetescrd
```

**That's it! :)**

### Useage in Docker Compose

For the latest example have a look at the `docker-compose.yml` file.

## Architecture

![OIDC ForwardAuth Middleware Architecture](https://github.com/espresso-lab/oidc-forward-auth-middleware/blob/main/docs/architecture.png?raw=true)

## Configuration

### Environment variables

#### General setting

| Environment variable      | Type    | Description                                                                                |
| ------------------------- | ------- | ------------------------------------------------------------------------------------------ |
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
