# Euno — GCP Config Connector (KRM) manifests
#
# Config Connector is a Kubernetes add-on that lets you manage GCP resources
# through Kubernetes resource manifests.  It is an alternative (or complement)
# to Terraform for teams that prefer a GitOps, Kubernetes-native workflow.
#
# Prerequisites
# -------------
# 1. Config Connector installed on the GKE cluster:
#    https://cloud.google.com/config-connector/docs/how-to/install-upgrade-uninstall
# 2. A Config Connector identity (service account) with the necessary IAM roles.
# 3. `kubectl` configured to reach the cluster.
#
# Usage
# -----
# Substitute <YOUR_PROJECT_ID> and <YOUR_REGION> in each manifest, then apply:
#
#   kubectl apply -f infra/gcp/config-connector/
#
# Config Connector will reconcile the manifests and create (or update) the
# corresponding GCP resources.  Watch progress with:
#
#   kubectl get -f infra/gcp/config-connector/ -w
#
# Order of application
# --------------------
# Apply in the order listed below.  Config Connector resolves inter-resource
# references automatically once the referenced resources are ready, but applying
# in dependency order reduces reconciliation time:
#
#   1. cloud-kms.yaml          — KMS key ring and signing key
#   2. artifact-registry.yaml  — Artifact Registry repository
#   3. cloud-sql.yaml          — Cloud SQL instance and database
#   4. memorystore.yaml        — Memorystore for Redis instance
#
# See also
# --------
# - infra/gcp/terraform/       — Terraform alternative
# - docs/deploy-gke.md         — Full GKE deployment guide
# - docs/secrets-gcp.md        — Secret Manager integration
