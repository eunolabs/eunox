# Incident Response Runbook

## Overview

This runbook provides step-by-step procedures for recognizing, responding to, and resolving security incidents involving AI agents in the Euno capability-native governance system.

**Target Audience:** Operations team, security operators, incident responders

**Last Updated:** 2026-04-27

---

## Table of Contents

1. [Alert Types and Recognition](#alert-types-and-recognition)
2. [Kill Switch Procedures](#kill-switch-procedures)
3. [Token Revocation Procedures](#token-revocation-procedures)
4. [Verification and Validation](#verification-and-validation)
5. [Communication and Escalation](#communication-and-escalation)
6. [Post-Incident Activities](#post-incident-activities)
7. [Appendix: Common Scenarios](#appendix-common-scenarios)

---

## Alert Types and Recognition

### Recognizing Agent Misbehavior

Watch for these alert types in your monitoring dashboards:

####  1. Repeated Denied Tool Requests
**Indicator:** Same agent repeatedly attempts unauthorized actions

**Log Pattern:**
```json
{
  "level": "info",
  "logType": "audit",
  "eventType": "denial",
  "decision": "deny",
  "agentId": "agent-xyz",
  "reason": "Insufficient permissions",
  "resource": "api://crm/customers",
  "action": "write"
}
```

**Actions:**
1. Check if multiple denials (>5) in short timeframe (< 1 minute)
2. Examine requested resources to identify escalation attempts
3. Consider killing agent if pattern suggests malicious intent

---

#### 2. Tool-Call Spikes After Suspicious Document
**Indicator:** Sudden increase in tool invocations following document ingestion

**Log Pattern:**
```json
{
  "agentId": "agent-abc",
  "toolInvocations": 50,
  "timeWindow": "60s",
  "previousAverage": 5
}
```

**Actions:**
1. Check document metadata for suspicious content
2. Review tool call targets (are they within expected scope?)
3. Activate session kill switch if calls target sensitive resources

---

#### 3. Write Attempts from Read-Only Sessions
**Indicator:** Write/delete attempts from sessions with read-only capabilities

**Log Pattern:**
```json
{
  "eventType": "denial",
  "decision": "deny",
  "sessionId": "sess-readonly-123",
  "action": "write",
  "reason": "Insufficient permissions"
}
```

**Actions:**
1. Verify session capability scope in original issuance
2. Check for token tampering (signature verification failures)
3. Revoke token immediately and kill session

---

#### 4. High-Sensitivity Label Retrieval
**Indicator:** Unauthorized identity attempts to retrieve high-sensitivity data

**Log Pattern:**
```json
{
  "eventType": "denial",
  "userId": "user@example.com",
  "resource": "storage://confidential/executive-docs",
  "sensitivityLabel": "Highly Confidential",
  "userClearanceLevel": "Standard"
}
```

**Actions:**
1. Confirm user identity and clearance level
2. Investigate how agent obtained reference to sensitive resource
3. Report to security team for potential insider threat investigation

---

## Kill Switch Procedures

### Global Kill Switch Activation

**When to Use:** System-wide emergency; multiple agents compromised; critical vulnerability discovered

#### Procedure

1. **Activate Global Kill Switch**
   ```bash
   curl -X POST http://tool-gateway:3002/admin/kill-switch/global/activate \
     -H "X-Admin-API-Key: ${ADMIN_API_KEY}"
   ```

2. **Verify Activation**
   - Check Tool Gateway logs for confirmation:
     ```
     [warn] Global kill switch activated via admin API
     ```
   - Test that agent requests are blocked:
     ```bash
     # Should return 403 Forbidden
     curl -X GET http://tool-gateway:3002/proxy/test \
       -H "Authorization: Bearer ${TEST_TOKEN}"
     ```

3. **Check Status**
   ```bash
   curl -X GET http://tool-gateway:3002/admin/kill-switch/status \
     -H "X-Admin-API-Key: ${ADMIN_API_KEY}"
   ```

   **Expected Response:**
   ```json
   {
     "globalKill": true,
     "killedSessions": [],
     "killedAgents": []
   }
   ```

4. **Observe Gateway Logs**
   - Monitor for 403 errors confirming blocks:
     ```bash
     kubectl logs -n euno-system deploy/tool-gateway --follow | grep "403"
     ```

---

### Session-Specific Kill

**When to Use:** Single compromised session; user reported suspicious agent behavior; isolated incident

#### Procedure

1. **Identify Session ID**
   - From audit logs:
     ```bash
     kubectl logs -n euno-system deploy/tool-gateway | \
       grep "agentId.*${AGENT_ID}" | jq '.sessionId'
     ```

2. **Kill Session**
   ```bash
   curl -X POST http://tool-gateway:3002/admin/kill-switch/session/${SESSION_ID}/kill \
     -H "X-Admin-API-Key: ${ADMIN_API_KEY}"
   ```

3. **Verify Kill**
   - Check logs:
     ```
     [warn] Session killed {"sessionId":"sess-123"}
     ```
   - Confirm subsequent requests are blocked:
     ```bash
     # Should return 403 Forbidden with reason
     curl -v http://tool-gateway:3002/proxy/test \
       -H "Authorization: Bearer ${SESSION_TOKEN}"
     ```

4. **Monitor for Evasion Attempts**
   - Watch for same agent trying to obtain new session
   - Consider agent-level kill if evasion detected

---

### Agent-Specific Kill

**When to Use:** Agent consistently misbehaves across sessions; agent identity compromised

#### Procedure

1. **Kill Agent**
   ```bash
   curl -X POST http://tool-gateway:3002/admin/kill-switch/agent/${AGENT_ID}/kill \
     -H "X-Admin-API-Key: ${ADMIN_API_KEY}"
   ```

2. **Verify Kill**
   - All current and future sessions for this agent are blocked
   - Check logs:
     ```
     [warn] Agent killed {"agentId":"agent-xyz"}
     ```

3. **Revoke All Agent Tokens** (Optional but recommended)
   - Query audit logs for all token IDs issued to agent:
     ```bash
     kubectl logs -n euno-system deploy/capability-issuer | \
       grep "agentId.*${AGENT_ID}" | jq '.tokenId' | \
       xargs -I {} curl -X POST http://tool-gateway:3002/admin/revoke \
         -H "X-Admin-API-Key: ${ADMIN_API_KEY}" \
         -H "Content-Type: application/json" \
         -d '{"tokenId":"{}"}'
     ```

---

### Reviving Killed Sessions/Agents

**When to Use:** False positive confirmed; testing complete; incident resolved

#### Procedure

1. **Revive Session**
   ```bash
   curl -X POST http://tool-gateway:3002/admin/kill-switch/session/${SESSION_ID}/revive \
     -H "X-Admin-API-Key: ${ADMIN_API_KEY}"
   ```

2. **Revive Agent**
   ```bash
   curl -X POST http://tool-gateway:3002/admin/kill-switch/agent/${AGENT_ID}/revive \
     -H "X-Admin-API-Key: ${ADMIN_API_KEY}"
     ```

3. **Verify Revival**
   - Test that legitimate requests succeed
   - Monitor for immediate misbehavior (may indicate persistent issue)

---

## Token Revocation Procedures

### Explicit Token Revocation

**When to Use:** Token compromised; user requests revocation; capability scope needs reduction

#### Procedure

1. **Extract Token ID (JTI)**
   - From audit log:
     ```bash
     kubectl logs -n euno-system deploy/capability-issuer | \
       grep "agentId.*${AGENT_ID}" | jq '.tokenId'
     ```
   - Or decode from token:
     ```bash
     echo ${TOKEN} | cut -d. -f2 | base64 -d | jq '.jti'
     ```

2. **Revoke Token**
   ```bash
   curl -X POST http://tool-gateway:3002/admin/revoke \
     -H "X-Admin-API-Key: ${ADMIN_API_KEY}" \
     -H "Content-Type: application/json" \
     -d '{
       "tokenId": "token-jti-here",
       "expiresAt": 1735689600
     }'
   ```

   **Parameters:**
   - `tokenId` (required): JWT ID (jti claim) from token
   - `expiresAt` (optional): Unix timestamp when token expires (defaults to 24h from now)

3. **Verify Revocation**
   - Attempt to use revoked token:
     ```bash
     # Should return 401 Unauthorized with "Token has been revoked"
     curl -v http://tool-gateway:3002/proxy/test \
       -H "Authorization: Bearer ${REVOKED_TOKEN}"
     ```

4. **Check Gateway Logs**
   ```
   [warn] Token revoked {"tokenId":"abc-123","expiresAt":1735689600}
   ```

---

### Distributed Revocation Sync

**Important:** In multi-instance deployments, each Tool Gateway replica maintains its own in-memory revocation list.

**Current State:** Revocations are NOT automatically synchronized across replicas.

**Workarounds:**
1. **Call revoke on each replica:**
   ```bash
   for replica in gateway-0 gateway-1 gateway-2; do
     kubectl exec -n euno-system $replica -- \
       curl -X POST http://localhost:3002/admin/revoke \
         -H "X-Admin-API-Key: ${ADMIN_API_KEY}" \
         -d '{"tokenId":"${TOKEN_ID}"}'
   done
   ```

2. **Use shared store (recommended for production):**
   - Replace in-memory Map with Redis
   - Override `isRevoked()` and `revokeToken()` in JWTTokenVerifier
   - See `/packages/tool-gateway/src/verifier.ts` comments

---

## Verification and Validation

### How to Verify Kill Took Effect

1. **Check Gateway Logs for 403 Errors**
   ```bash
   kubectl logs -n euno-system deploy/tool-gateway --tail=50 | grep "403\|Session killed\|Agent killed"
   ```

2. **Test with Known Token**
   ```bash
   # Should return 403 Forbidden
   curl -v http://tool-gateway:3002/proxy/test \
     -H "Authorization: Bearer ${AGENT_TOKEN}"
   ```

   **Expected Response:**
   ```json
   {
     "error": {
       "code": "FORBIDDEN",
       "message": "Session has been killed"
     }
   }
   ```

3. **Check Kill Switch Status**
   ```bash
   curl http://tool-gateway:3002/admin/kill-switch/status \
     -H "X-Admin-API-Key: ${ADMIN_API_KEY}" | jq
   ```

4. **Monitor Audit Logs**
   - Look for denial events with kill switch reason
   - Confirm no successful actions from killed agent/session

---

## Communication and Escalation

### Step 1: Initial Notification

**Who to notify:**
- On-call security engineer
- Operations lead
- Product owner (if user-facing impact)

**Communication Template:**
```
INCIDENT ALERT: Agent ${AGENT_ID} exhibiting suspicious behavior
Severity: ${HIGH|MEDIUM|LOW}
Description: ${BRIEF_DESCRIPTION}
Actions Taken: ${KILL_SWITCH_STATUS}
Current Status: ${CONTAINED|IN_PROGRESS|ESCALATING}
Next Steps: ${PLANNED_ACTIONS}
```

### Step 2: Escalation Criteria

Escalate to **Security Team Lead** if:
- Multiple agents compromised
- Sensitive data accessed
- Token tampering detected
- Persistence mechanism discovered

Escalate to **VP Engineering** if:
- Customer data breach suspected
- Regulatory reporting required
- Media attention likely

### Step 3: External Communication

**Do NOT** communicate externally without approval from:
- Legal team
- Communications team
- Executive leadership

---

## Post-Incident Activities

### 1. Incident Review

**Within 24 hours:**
- Document timeline of events
- Identify root cause
- Assess effectiveness of response
- Capture lessons learned

### 2. Evidence Preservation

**Preserve for analysis:**
- Audit logs from time window
- Cryptographic evidence signatures
- Token payloads
- Agent manifests

```bash
# Export audit logs
# Note: `kubectl logs` supports --since-time but not --until; filter the upper bound with awk.
kubectl logs -n euno-system deploy/tool-gateway \
  --since-time="${INCIDENT_START}" --timestamps=true \
  | awk -v end="${INCIDENT_END}" '$1 <= end { print }' \
  > incident-${DATE}-gateway-logs.json

kubectl logs -n euno-system deploy/capability-issuer \
  --since-time="${INCIDENT_START}" --timestamps=true \
  | awk -v end="${INCIDENT_END}" '$1 <= end { print }' \
  > incident-${DATE}-issuer-logs.json
```

### 3. Remediation

- Patch vulnerabilities discovered
- Update detection rules
- Improve monitoring coverage
- Enhance agent constraints if needed

### 4. Documentation

- Update runbook with new procedures
- Add scenario to appendix
- Share findings with team
- Update incident response training

---

## Appendix: Common Scenarios

### Scenario A: Runaway Agent After Malicious Document

**Symptoms:**
- Sudden spike in tool invocations
- Repeated attempts to access unrelated resources
- High CPU usage on agent pod

**Response:**
1. Activate session kill switch immediately
2. Isolate document for analysis
3. Review all actions taken by agent
4. Revoke all tokens issued for this session
5. Scan for similar documents in other agent contexts

---

### Scenario B: Token Leakage to External System

**Symptoms:**
- Capability token detected in external logs
- Unusual network traffic from agent pod
- Requests from unexpected IP addresses

**Response:**
1. Revoke compromised token immediately
2. Activate agent kill switch
3. Review network policies
4. Investigate data exfiltration
5. Rotate signing keys if widespread

---

### Scenario C: Insider Threat - Privilege Escalation Attempt

**Symptoms:**
- Low-privileged user requesting high-privilege capabilities
- Capability requests inconsistent with user role
- Off-hours activity from sensitive account

**Response:**
1. Do NOT kill immediately (may tip off insider)
2. Enable enhanced logging for user
3. Coordinate with HR/Security for investigation
4. Prepare to revoke all user tokens on demand
5. Document evidence chain carefully

---

### Scenario D: False Positive - Legitimate Burst Activity

**Symptoms:**
- High tool call rate during known batch operation
- Pattern matches legitimate use case
- User confirms expected behavior

**Response:**
1. Validate with user/team lead
2. Review capability scope (may be too restrictive)
3. Update alert thresholds if needed
4. Document in runbook for future reference
5. Consider allow-listing for known batch jobs

---

## Quick Reference Card

### Emergency Commands

```bash
# Global kill switch
curl -X POST $GATEWAY/admin/kill-switch/global/activate \
  -H "X-Admin-API-Key: $KEY"

# Kill session
curl -X POST $GATEWAY/admin/kill-switch/session/$SESS_ID/kill \
  -H "X-Admin-API-Key: $KEY"

# Kill agent
curl -X POST $GATEWAY/admin/kill-switch/agent/$AGENT_ID/kill \
  -H "X-Admin-API-Key: $KEY"

# Revoke token
curl -X POST $GATEWAY/admin/revoke \
  -H "X-Admin-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"tokenId":"$TOKEN_ID"}'

# Check status
curl $GATEWAY/admin/kill-switch/status -H "X-Admin-API-Key: $KEY"
```

### Key Log Locations

```bash
# Tool Gateway logs
kubectl logs -n euno-system deploy/tool-gateway --follow

# Capability Issuer logs
kubectl logs -n euno-system deploy/capability-issuer --follow

# Audit logs (JSON structured)
kubectl logs -n euno-system deploy/tool-gateway | grep '"logType":"audit"'
```

---

## Support Contacts

| Role | Contact | Availability |
|------|---------|-------------|
| On-Call Security Engineer | security-oncall@example.com | 24/7 |
| Operations Lead | ops-lead@example.com | Business hours |
| Security Team Lead | security-lead@example.com | Emergency escalation |
| VP Engineering | vp-eng@example.com | Critical incidents only |

---

**Document Version:** 1.0
**Last Reviewed:** 2026-04-27
**Next Review:** 2026-07-27
**Owner:** Security Operations Team
