# Traefik OIDC ForwardAuth Middleware



## Purpose

### Problem
- No easy solution for OIDC in traefik
- Traefik enterprise is not open source
- OIDC proxy requires many code changes in the applications manifest files


### Solution
Purpose of the project is to provide an easy and powerfull solution, to protect applications in a Kubernetes cluster with a Traefik ingress controller with an OIDC authentication mechanism without changing the application code.


## Test

```bash
# HTTP 200
curl --cookie "traefik_oidc=1" -v http://127.0.0.1:8080/authorize

# HTTP 307
curl --cookie "traefik_oidc=12345" -v http://127.0.0.1:8080/authorize
```
