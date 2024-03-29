# Traefik OIDC ForwardAuth Middleware

## Purpose

### Problem

- No easy solution for OIDC in traefik
- Traefik enterprise is not open source
- OIDC proxy requires many code changes in the applications manifest files

### Solution

Purpose of the project is to provide an easy and powerfull solution, to protect applications in a Kubernetes cluster with a Traefik ingress controller with an OIDC authentication mechanism without changing the application code.

## Test

Have a look at the verify.http file
