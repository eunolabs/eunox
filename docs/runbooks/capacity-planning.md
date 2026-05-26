# Runbook: Capacity Planning

**Severity**: P3 — Advisory  
**Last Updated**: 2026-05-26  
**Owner**: Platform Engineering

## Overview

This runbook provides guidelines for scaling the Eunox platform based on traffic patterns, resource utilization, and growth projections.

## Service Scaling Characteristics

| Service               | Scaling Dimension  | Stateful     | Bottleneck                    |
| --------------------- | ------------------ | ------------ | ----------------------------- |
| Gateway               | Requests/second    | No           | CPU (JWT verification, DPoP)  |
| Issuer                | Token issuance/min | No           | CPU (ECDSA signing)           |
| Minter                | Key operations/min | No           | Database connections          |
| DB Token Service      | Token grants/min   | No           | Cloud provider API limits     |
| Storage Grant Service | Grant requests/min | No           | Cloud provider API limits     |
| Posture Emitter       | Events/min         | Yes (SQLite) | Single-writer (1 replica max) |

## Resource Sizing Guidelines

### Gateway

| Traffic Tier | Replicas | CPU Request | Memory Request | Notes                      |
| ------------ | -------- | ----------- | -------------- | -------------------------- |
| < 100 RPS    | 2        | 100m        | 128Mi          | Minimum HA                 |
| 100–500 RPS  | 3–5      | 250m        | 256Mi          | HPA handles bursts         |
| 500–2000 RPS | 5–10     | 500m        | 512Mi          | Consider dedicated nodes   |
| > 2000 RPS   | 10+      | 1000m       | 1Gi            | Multi-zone, dedicated pool |

### Issuer

| Traffic Tier   | Replicas | CPU Request | Memory Request |
| -------------- | -------- | ----------- | -------------- |
| < 10 tokens/s  | 2        | 100m        | 128Mi          |
| 10–50 tokens/s | 3        | 250m        | 256Mi          |
| > 50 tokens/s  | 5+       | 500m        | 512Mi          |

### Database (PostgreSQL)

| Data Volume | Instance Type | Storage    | Connections |
| ----------- | ------------- | ---------- | ----------- |
| < 1M keys   | db.t3.medium  | 50 GB gp3  | 100         |
| 1–10M keys  | db.r6g.large  | 200 GB gp3 | 200         |
| > 10M keys  | db.r6g.xlarge | 500 GB io2 | 500         |

### Redis

| Use Case                | Instance Type    | Memory | Cluster Mode       |
| ----------------------- | ---------------- | ------ | ------------------ |
| Dev/Test                | cache.t3.small   | 1.5 GB | No                 |
| Production (< 1000 RPS) | cache.r6g.large  | 13 GB  | Sentinel (3 nodes) |
| Production (> 1000 RPS) | cache.r6g.xlarge | 26 GB  | Cluster (6 nodes)  |

## HPA Configuration

The gateway HPA is configured with:

- **Scale-up**: 70% CPU utilization triggers scale-up
- **Scale-down**: Stabilization window of 300s prevents flapping
- **Min replicas**: 2 (HA minimum)
- **Max replicas**: 10 (adjust based on budget)

### Tuning HPA

```bash
# Check current HPA status
kubectl -n eunox-system get hpa eunox-gateway

# View scaling events
kubectl -n eunox-system describe hpa eunox-gateway

# Adjust thresholds
helm upgrade eunox k8s/helm/eunox/ \
  --set gateway.hpa.targetCPU=60 \
  --set gateway.hpa.maxReplicas=20
```

## Monitoring Signals for Scaling

### Scale Up When

- CPU utilization > 70% sustained for 5 minutes
- Request latency p99 > 50ms
- HTTP 429 (rate limited) responses increasing
- Queue depth growing (Redis-backed services)

### Scale Down When

- CPU utilization < 30% for 15 minutes
- No 429 responses
- Latency well within SLO

## Forecasting

### Traffic Growth Model

```
projected_rps = current_rps * (1 + monthly_growth_rate) ^ months_ahead
```

Typical growth rates:

- Organic: 5–10% monthly
- After launch/expansion: 20–50% monthly
- Enterprise onboarding: Step function (predict from pipeline)

### Capacity Planning Process

1. **Monthly**: Review metrics dashboards for trends
2. **Quarterly**: Project 6-month resource needs
3. **Annually**: Budget for infrastructure growth
4. **Ad-hoc**: Before major launches or customer onboarding

## Cost Optimization

- Use Spot/Preemptible instances for non-critical workloads (posture-emitter)
- Right-size instances based on actual utilization (not peaks)
- Use reserved instances for baseline capacity
- Implement request coalescing for high-throughput scenarios
- Consider geographic distribution for latency-sensitive deployments
