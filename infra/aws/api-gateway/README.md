# AWS Tool-Gateway profile (Sprint-1 v1)

This directory contains the **AWS API Gateway** profile that is the AWS
parity of the Azure APIM `validate-jwt` policy referenced in the Sprint-1
plan. It is the cloud-edge front door for the in-cluster Tool Gateway
service (`euno-platform/packages/tool-gateway`).

| File                 | Purpose                                                                                             |
|----------------------|-----------------------------------------------------------------------------------------------------|
| `openapi.json`       | OpenAPI 3.0 document with API Gateway extensions, importable via `aws apigateway import-rest-api`. |
| `lambda-authorizer.js` | Lambda authorizer source (Node.js 20.x). Verifies the capability JWT at the edge.                 |

## Flow

```
client ──HTTPS──▶ API Gateway (REST)
                      │
                      ├──▶ EunoCapabilityAuthorizer (Lambda)
                      │       └─ jose.jwtVerify(token, JWKS, { iss, aud })
                      │
                      └──▶ VPC Link ──▶ Tool Gateway pod (EKS)
                                          └─ scope-based payload validation
                                              (euno-platform/packages/tool-gateway/src/enforcement.ts)
```

This mirrors the Sprint-1 Azure pipeline (APIM `validate-jwt` + tool-gateway
container) one-for-one: signature/expiry/audience/issuer checks happen at
the edge; scope-based payload validation stays inside the Tool Gateway pod
so the policy lives in exactly one place.

## Deployment

1. **Provision infra** with `infra/terraform/aws/` (creates the EKS
   cluster, ECR, KMS signing key, etc.).
2. **Build and zip** the authorizer (with `jose` in `node_modules`):

   ```bash
   cd infra/aws/api-gateway
   mkdir -p build && cp lambda-authorizer.js build/index.js
   cd build && npm init -y && npm install jose@5
   zip -r ../authorizer.zip .
   ```

3. **Deploy the Lambda**:

   ```bash
   aws lambda create-function \
     --function-name euno-capability-authorizer \
     --runtime nodejs20.x \
     --handler index.handler \
     --role <execution-role-arn> \
     --zip-file fileb://authorizer.zip \
     --environment "Variables={ISSUER_JWKS_URL=https://issuer.euno.example/.well-known/jwks.json,EXPECTED_AUDIENCE=tool-gateway,EXPECTED_ISSUER=https://issuer.euno.example}"
   ```

4. **Import the API**:

   ```bash
   # Substitute placeholders in openapi.json first (UPSTREAM_TOOL_GATEWAY_URL,
   # VPC_LINK_ID, AUTHORIZER_LAMBDA_ARN, AWS_REGION, API_GATEWAY_INVOKE_ROLE_ARN).
   envsubst < openapi.json > openapi.rendered.json
   aws apigateway import-rest-api \
     --body fileb://openapi.rendered.json
   ```

5. **Create the deployment + stage** as usual.

## Exit criteria parity

The following exit criteria apply here:

* Valid token with correct scope → action allowed (200 from upstream).
* Missing/invalid/expired token → 401 from API Gateway directly.
* Token verified but lacks scope → 403 from the Tool Gateway pod.
* CloudWatch logs (the API Gateway `AWS::ApiGateway::Stage` access-log
  destination) record every authorization decision — see the Logs Insights
  queries in `infra/aws/security/cloudwatch-logs-insights.json`.
