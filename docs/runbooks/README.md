# Operational Runbooks

This directory contains operational runbooks for the Eunox platform. Each runbook covers a specific operational scenario with step-by-step procedures.

## Index

| Runbook                                     | Description                                          | Severity |
| ------------------------------------------- | ---------------------------------------------------- | -------- |
| [Kill Switch](./kill-switch.md)             | Emergency policy override to block all enforcement   | P1       |
| [Key Rotation](./key-rotation.md)           | Rotating signing keys, API keys, and HMAC secrets    | P2       |
| [Disaster Recovery](./disaster-recovery.md) | Recovery procedures for data loss or service failure | P1       |
| [Capacity Planning](./capacity-planning.md) | Scaling guidelines and resource forecasting          | P3       |

## Conventions

- **Severity**: P1 = immediate action needed, P2 = planned maintenance, P3 = advisory
- All commands assume `kubectl` is configured for the target cluster
- Helm release name is assumed to be `eunox` (adjust as needed)
- Namespace is assumed to be `eunox-system`
