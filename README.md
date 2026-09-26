# Cloudflare Malicious IP Reputation Worker

A Cloudflare Worker that automatically detects, classifies, caches, and blocks potentially malicious IP addresses using **Blackbox IP reputation intelligence** and **Cloudflare IP Lists**.

The Worker operates at the Cloudflare edge and combines two detection mechanisms:

1. **IP reputation checking** using Blackbox.
2. **Scanner/probe detection** based on suspicious request paths.

Suspicious IPs are automatically added to a Cloudflare IP List, allowing the IP to be blocked by Cloudflare security rules across protected applications.

---

## How It Works

```text
                         Internet
                             |
                             v
                    +------------------+
                    |    Cloudflare    |
                    |      Worker      |
                    +--------+---------+
                             |
                    CF-Connecting-IP
                             |
                             v
                  +--------------------+
                  |   Cloudflare KV    |
                  | IP Reputation Cache|
                  +---------+----------+
                            |
              +-------------+-------------+
              |                           |
          Cached IP                  New IP
              |                           |
       +------+-------+                   |
       |              |                   |
   Suspicious       Clean                 v
       |              |           +---------------+
       v              v           |    Blackbox   |
    403 Block       Allow         | IP Reputation |
                                  +-------+-------+
                                          |
                              +-----------+-----------+
                              |                       |
                         Suspicious                 Clean
                              |                       |
                              v                       v
                    Cloudflare IP List             Cache
                              |
                              v
                         Future 403s
```

---

# Features

- Detects malicious/suspicious IP addresses.
- Uses Blackbox IP reputation data.
- Caches IP reputation results in Cloudflare KV.
- Avoids making the client wait for reputation checks.
- Detects suspicious scanner/probe paths immediately.
- Automatically adds suspicious IPs to a Cloudflare IP List.
- Cached suspicious IPs are immediately blocked.
- Cached clean IPs bypass external reputation checks.
- Scanner detection overrides an existing clean reputation result.
- Uses `ctx.waitUntil()` for asynchronous reputation checks.
- Runs entirely at the Cloudflare edge.
- No backend application changes are required.
- Can detect WordPress scanning attempts when the protected website **does not use WordPress**.

---

# Detection Methods

## 1. Blackbox IP Reputation

When an IP is seen for the first time, the Worker asynchronously queries:

```text
https://blackbox.ipinfo.app/api/v3beta/{IP}
```

The returned information is normalized and stored in KV.

Example stored result:

```json
{
  "ip": "1.2.3.4",
  "suspicious": true,
  "classification": "vpn",
  "confidence": 0.714,
  "asn": "AS12345",
  "categories": {},
  "signals": {},
  "evidence": [],
  "checked_at": "2026-09-26T12:00:00.000Z"
}
```

If Blackbox reports:

```json
{
  "suspicious": true
}
```

the IP is added to the configured Cloudflare IP List.

---

# 2. Scanner / Probe Detection

The Worker also detects suspicious paths independently of Blackbox.

The current detection rules are:

```text
.env
.git
.py
cgn
wp
```

### WordPress Detection

The `wp` check is intended for websites that **do not use WordPress**.

If your application is not running WordPress, requests such as:

```text
/wp-admin/
/wp-login.php
/wp-content/
/wp-includes/
/wordpress/
```

are strong indicators that an automated scanner is probing the application for a WordPress installation.

In that situation, the Worker can immediately block the request and flag the source IP.

**Important:** If the protected website actually uses WordPress, do **not** enable the `wp` probe rule, because legitimate WordPress requests may contain `wp` paths.

The implementation can therefore be configured so that the WordPress rule is enabled only for non-WordPress applications.

---

## Scanner Examples

For a non-WordPress application, examples include:

```text
/wp-admin/
```

```text
/wp-login.php
```

```text
/.env
```

```text
/.git/config
```

```text
/test.py
```

```text
/cgn/
```

These requests are blocked immediately with:

```http
HTTP/1.1 403 Forbidden
```

The IP is also asynchronously:

1. Stored in KV as suspicious.
2. Added to the Cloudflare IP List.

---

# Request Processing Logic

The Worker follows this flow.

## Step 1 — Get Client IP

The Worker retrieves:

```javascript
request.headers.get("CF-Connecting-IP")
```

If Cloudflare does not provide an IP, the request is passed through normally.

---

## Step 2 — Check KV

The Worker creates:

```text
ip:{IP}
```

and checks the `IP_REPUTATION_CACHE` KV namespace.

---

## Step 3 — Previously Suspicious IP

If KV contains:

```json
{
  "suspicious": true
}
```

the request is immediately rejected:

```text
403 Forbidden
```

No external API request is required.

---

## Step 4 — Scanner Probe

If the IP is not already blocked but the requested path matches the scanner detection rules, the Worker immediately returns:

```text
403 Forbidden
```

At the same time, the Worker asynchronously flags the IP.

This means the attacker does not need to wait for the Blackbox API.

---

## Step 5 — Previously Checked Clean IP

If the IP exists in KV and is not suspicious, the request is allowed normally.

The Worker does not query Blackbox again until the cache expires.

---

## Step 6 — New IP

If the IP has never been seen before:

```text
Client Request
      |
      +----> Allow request immediately
      |
      +----> Background Blackbox check
```

The first request is **not** delayed while waiting for Blackbox.

This is implemented using:

```javascript
ctx.waitUntil(
  checkIP(ip, env)
);
```

---

# KV Cache

The Worker uses Cloudflare KV to cache reputation results.

Each IP is stored using:

```text
ip:{IP}
```

Example:

```text
ip:8.8.8.8
```

The cache expiration is:

```text
86400 seconds
```

which equals:

```text
24 hours
```

This prevents the Worker from querying Blackbox on every request.

---

# Cloudflare IP List

When an IP is determined to be suspicious, it is added to a Cloudflare IP List through the Cloudflare API.

The API endpoint used is:

```text
/accounts/{CF_ACCOUNT_ID}/rules/lists/{CF_LIST_ID}/items
```

The Worker sends the IP together with a comment containing information such as:

```text
Blackbox suspicious |
classification=vpn |
confidence=0.714 |
evidence=...
```

This provides additional visibility when reviewing the Cloudflare IP List.

---

# Environment Variables / Worker Bindings

The Worker requires the following configuration.

| Variable / Binding | Type | Description |
|---|---|---|
| `IP_REPUTATION_CACHE` | KV Namespace | Stores IP reputation results |
| `CF_ACCOUNT_ID` | Secret / Variable | Cloudflare account ID |
| `CF_LIST_ID` | Secret / Variable | ID of the Cloudflare IP List |
| `CF_API_TOKEN` | Secret | Cloudflare API token used to update the list |

---

# Cloudflare KV

Create a KV namespace for:

```text
IP_REPUTATION_CACHE
```

The Worker expects the binding to have exactly this name:

```text
IP_REPUTATION_CACHE
```

The Worker uses:

```javascript
env.IP_REPUTATION_CACHE.get(...)
```

and:

```javascript
env.IP_REPUTATION_CACHE.put(...)
```

---

# Cloudflare API Token

The Worker needs a Cloudflare API token capable of modifying the target IP List.

The token should follow the **principle of least privilege** and only have the permissions required to manage the intended list.

Do not hard-code the token in the Worker source code.

Use a Worker secret:

```text
CF_API_TOKEN
```

Never commit the token to GitHub.

---

# Cloudflare IP List

Create a Cloudflare IP List that will contain suspicious IP addresses.

For example:

```text
$malware
```

The Worker adds detected IP addresses to this list.

The list can then be referenced from Cloudflare security rules.

For example:

```text
IP in $malware
```

with the action:

```text
Block
```

This separates **detection** from **enforcement**:

```text
Worker
  |
  | detects malicious IP
  v
Cloudflare IP List
  |
  | referenced by security rule
  v
Cloudflare
  |
  v
Block
```

---

# Important: Worker Blocking vs IP List Blocking

The Worker itself immediately blocks:

- Known suspicious IPs in KV.
- Scanner/probe requests.

It also adds suspicious IPs to the Cloudflare IP List.

The IP List can then provide broader enforcement through Cloudflare security rules.

This means the system has two layers:

```text
Layer 1
Worker
  ↓
Immediate 403

Layer 2
Cloudflare IP List
  ↓
Cloudflare security rule
  ↓
Block future requests
```

---

# Example Detection

Suppose an attacker requests:

```text
https://example.com/.env
```

The Worker extracts:

```text
IP = 203.0.113.50
```

The path matches:

```javascript
pathname.includes(".env")
```

The Worker immediately returns:

```http
403 Forbidden
```

At the same time:

```text
203.0.113.50
       |
       +--> KV
       |    suspicious=true
       |
       +--> Cloudflare IP List
            203.0.113.50
```

A later request from the same IP:

```text
https://example.com/login
```

will hit the KV entry:

```json
{
  "suspicious": true
}
```

and will therefore also receive:

```http
403 Forbidden
```

The attacker does not need to request another suspicious path.

---

# Clean IP Example

For a normal first-time visitor:

```text
203.0.113.20
       |
       v
Worker
       |
       v
No KV entry
       |
       +--------------------+
       |                    |
       v                    v
 Allow request         Blackbox check
                            |
                            v
                         Clean
                            |
                            v
                           KV
```

The visitor does not wait for the Blackbox response.

---

# Suspicious Blackbox Example

If Blackbox returns:

```json
{
  "suspicious": true,
  "classification": "hosting",
  "confidence": 0.92
}
```

the Worker stores the result in KV and adds the IP to the Cloudflare list.

Future requests from the IP are blocked by the Worker based on the cached result.

---

# Error Handling

The Worker is designed to fail open when external reputation services are unavailable.

For example, if Blackbox returns:

```text
HTTP 500
```

the Worker logs the error and does not block the request solely because the reputation service failed.

Similarly, if the Cloudflare List API fails, the request processing itself is not interrupted.

This prevents an external reputation service outage from becoming an application outage.

---

# Security Considerations

## Protect the API Token

Never place:

```text
CF_API_TOKEN
```

directly inside the JavaScript source.

Use Cloudflare Worker secrets.

---

## Least Privilege

The Cloudflare API token should only have permissions necessary for managing the intended IP List.

Avoid using an unrestricted Global API Key.

---

## KV Is a Cache

KV should be considered a cache rather than the authoritative security database.

The Cloudflare IP List provides a persistent enforcement mechanism while KV provides fast Worker-side decisions.

---

# False Positives

Automated detection can produce false positives.

The most important rule to review is the WordPress detection rule.

If your website **does not use WordPress**, probing paths such as:

```text
/wp-admin/
/wp-login.php
/wp-content/
/wp-includes/
```

are generally useful scanner indicators.

If your website **does use WordPress**, the `wp` rule should be disabled.

The same principle applies to the other detection patterns. Review them against the applications protected by the Worker.

The current logic is intentionally simple:

```javascript
const isProbe =
  pathname.includes("wp") ||
  pathname.includes(".env") ||
  pathname.includes(".git") ||
  pathname.includes(".py") ||
  pathname.includes("cgn");
```

For production environments, these rules can be refined using exact paths, extensions, regular expressions, or allowlists where appropriate.

---

# WordPress Rule Configuration

For a **non-WordPress application**, the `wp` rule can remain enabled:

```javascript
const isProbe =
  pathname.includes("wp") ||
  pathname.includes(".env") ||
  pathname.includes(".git") ||
  pathname.includes(".py") ||
  pathname.includes("cgn");
```

For a **WordPress application**, remove the `wp` condition:

```javascript
const isProbe =
  pathname.includes(".env") ||
  pathname.includes(".git") ||
  pathname.includes(".py") ||
  pathname.includes("cgn");
```

This prevents legitimate WordPress traffic from being classified as scanner activity.

---

# Performance

The Worker is designed to minimize request latency.

For a new IP:

```text
Request
  |
  +--> Allow immediately
  |
  +--> Background reputation check
```

For a cached IP:

```text
Request
  |
  +--> KV lookup
  |
  +--> Allow / Block
```

For a scanner probe:

```text
Request
  |
  +--> Detect probe
  |
  +--> 403 immediately
  |
  +--> Background flagging
```

The use of:

```javascript
ctx.waitUntil(...)
```

allows background processing without making the client wait for the reputation lookup or Cloudflare List update.

---

# Logging

The Worker logs important events using:

```javascript
console.log()
```

and:

```javascript
console.error()
```

Examples include:

```text
Blackbox result: {...}
```

```text
Added 1.2.3.4 to Cloudflare IP list
```

```text
Blackbox HTTP 500 for 1.2.3.4
```

```text
Failed to flag 1.2.3.4
```

These logs can be reviewed using Cloudflare Worker observability/logging.

---

# Deployment

The Worker can be deployed through the Cloudflare dashboard or Wrangler.

Required components:

```text
Cloudflare Worker
       |
       +--- KV Namespace
       |      IP_REPUTATION_CACHE
       |
       +--- Worker Secrets
       |      CF_API_TOKEN
       |
       +--- Worker Variables
       |      CF_ACCOUNT_ID
       |      CF_LIST_ID
       |
       +--- Cloudflare IP List
              $malware
```

---

# Recommended Cloudflare Flow

A complete deployment can look like:

```text
                         Internet
                             |
                             v
                    +----------------+
                    |   Cloudflare   |
                    +-------+--------+
                            |
                            v
                    +---------------+
                    | Cloudflare    |
                    |    Worker     |
                    +-------+-------+
                            |
             +--------------+--------------+
             |                             |
             v                             v
        Scanner Probe                 KV Lookup
             |                             |
             v                    +--------+--------+
             |                    |                 |
             v                    v                 v
            403               Suspicious          New IP
                                  |                 |
                                  v                 v
                                 403              Blackbox
                                                     |
                                          +----------+----------+
                                          |                     |
                                          v                     v
                                     Suspicious                Clean
                                          |
                                          v
                                  Cloudflare IP List
                                          |
                                          v
                                  Cloudflare Rule
                                          |
                                          v
                                        Block
```

---

# Current Probe Detection

The current implementation detects requests containing:

| Pattern | Example | Recommended Usage |
|---|---|---|
| `wp` | `/wp-admin/` | Enable when the application does **not** use WordPress |
| `.env` | `/.env` | Generally suspicious |
| `.git` | `/.git/config` | Generally suspicious |
| `.py` | `/test.py` | Review for your application |
| `cgn` | `/cgn/...` | Review for your application |

These checks are case-insensitive because the pathname is normalized using:

```javascript
.toLowerCase()
```

---

# Limitations

This Worker is not a complete intrusion detection system.

It currently does not:

- Inspect request bodies.
- Analyze authentication failures.
- Perform malware scanning of uploaded files.
- Execute files in a sandbox.
- Inspect application-layer payloads.
- Guarantee that every suspicious IP is malicious.
- Replace a properly configured WAF.
- Replace application security controls.
- Perform continuous reputation checks while an IP remains cached.

The Worker is intended as an additional automated IP-reputation and scanner-detection layer.

---

# Architecture Summary

The core security model is:

```text
                    ┌──────────────────────┐
                    │       Request        │
                    └──────────┬───────────┘
                               │
                               v
                    ┌──────────────────────┐
                    │ Extract Client IP    │
                    └──────────┬───────────┘
                               │
                               v
                    ┌──────────────────────┐
                    │      KV Lookup       │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              v                v                v
        Suspicious          Scanner           New IP
              │              Probe               │
              v                │                 v
            403                v             Blackbox
                               │                 │
                               v                 v
                              403          Suspicious?
                                                 │
                                      ┌──────────┴──────────┐
                                      │                     │
                                     Yes                    No
                                      │                     │
                                      v                     v
                               Cloudflare List             KV
                                      │
                                      v
                                   Block
```

---

# Recommended Production Enhancements

Possible future improvements include:

- Configurable probe patterns.
- Separate configuration for WordPress/non-WordPress applications.
- Rate-based detection.
- Login brute-force detection.
- ASN-based detection.
- Country/region-based policies.
- Additional reputation providers.
- Automatic expiry/removal from the Cloudflare IP List.
- Allowlisting trusted IPs.
- Better scanner fingerprinting.
- Request-method analysis.
- User-Agent analysis.
- Bot-score integration.
- Cloudflare WAF integration.
- Security event analytics.
- Alerting through email, Slack, or another monitoring system.

---

# License
```text
MIT License
```
---

# Disclaimer

IP reputation data and automated scanner detection can produce false positives or false negatives.

The Worker should be deployed alongside normal Cloudflare security controls, application authentication, rate limiting, logging, monitoring, and secure application development practices.

Review the detection patterns and Cloudflare enforcement rules before using the Worker in a production environment.
