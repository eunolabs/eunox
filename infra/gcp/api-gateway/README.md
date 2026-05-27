# GCP Tool-Gateway profile (Sprint-1 v1)

This directory contains the **GCP** profile that is the GCP parity of the
Azure APIM `validate-jwt` policy referenced in the Sprint-1 plan. Two
deployment targets are supported because GCP exposes two production-ready
gateways:

| File                      | Target          | Purpose                                                           |
| ------------------------- | --------------- | ----------------------------------------------------------------- |
| `openapi.yaml`            | GCP API Gateway | OpenAPI 2.0 with `securityDefinitions: jwt`. Native JWKS support. |
| `apigee-validate-jwt.xml` | Apigee X        | Drop-in `VerifyJWT` policy, mirrors APIM `validate-jwt`.          |

Both verify the capability token at the cloud edge (signature, `iss`,
`aud`, `exp`) and forward valid requests to the in-cluster Tool Gateway
pod where scope-based payload validation runs (so the authorization
policy stays in exactly one place).

## API Gateway deployment

```bash
# 1. Provision infra (creates the GKE cluster, KMS signing key, etc).
cd infra/terraform/gcp && terraform apply

# 2. Substitute placeholders in openapi.yaml (UPSTREAM_TOOL_GATEWAY_URL,
#    ISSUER_URL).
envsubst < openapi.yaml > openapi.rendered.yaml

# 3. Create the API + config + gateway.
gcloud api-gateway apis create eunox-tool-gateway
gcloud api-gateway api-configs create v1 \
  --api=eunox-tool-gateway \
  --openapi-spec=openapi.rendered.yaml
gcloud api-gateway gateways create eunox-tool-gateway-gw \
  --api=eunox-tool-gateway --api-config=v1 \
  --location=us-central1
```

## Apigee deployment

Bundle `apigee-validate-jwt.xml` under `apiproxy/policies/` of an Apigee
proxy bundle and add a `<Step>` referencing `VerifyCapabilityToken` to
the proxy PreFlow. Then deploy the bundle with:

```bash
apigeecli apis create bundle -f apiproxy -n eunox-tool-gateway \
  --org $APIGEE_ORG --token $(gcloud auth print-access-token)
apigeecli apis deploy --name eunox-tool-gateway --rev 1 \
  --env $APIGEE_ENV --org $APIGEE_ORG \
  --token $(gcloud auth print-access-token)
```

## Exit criteria parity

The following exit criteria apply:

- Valid token with correct scope → action allowed (200 from upstream).
- Missing/invalid/expired token → 401 directly from API Gateway / Apigee.
- Token verified but lacks scope → 403 from the Tool Gateway pod.
- Cloud Logging records every authorization decision — see the Logs
  Explorer queries in `../security/cloud-logging-queries.json`.
