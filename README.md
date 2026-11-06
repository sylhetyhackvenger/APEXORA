
# APEXORA - Multi-Layer Firewall Analysis · Offensive & Defensive Security Intelligence · Attack-Surface Discovery & Advanced Penetration Testing Framework

---

## Overview

APEXORA is a comprehensive offensive security research framework engineered for authorized penetration testers, gray teams, bug bounty hunters, and security researchers who need a single cohesive toolchain for end-to-end attack-surface analysis. It unifies WAF fingerprinting across 160+ enterprise and cloud signatures, 60+ vulnerability categories with hundreds of curated payloads, protocol-level smuggling probes, client-side DOM analysis, CVE exploitation for 24 high-profile vulnerabilities (17 with executable HTTP chains), multi-layer DDoS simulation with a real-time ASCII dashboard, out-of-band blind vulnerability detection, and rate-limited reconnaissance designed to avoid triggering defensive filters. Whether you are mapping a web application's defensive posture, validating a patch cycle, or hunting for critical logic flaws across multi-target portfolios, APEXORA delivers the depth, speed, and reliability required for professional engagements. Built in pure Python 3 with zero external dependencies, it runs anywhere Python runs — from a hardened jump host to a Raspberry Pi — with a SQLite-backed history engine, session-token authentication, scope allowlisting, and automatic terminal-session recording in TXT, JSON, and XML formats. Every module is engineered for authorized, scoped, non-destructive testing, and every action is logged, gated, and auditable.

---

## Table of Contents

- [Core Capabilities](#core-capabilities)
- [Installation](#installation)
- [Authentication & Scope](#authentication--scope)
- [Rate Limiting](#rate-limiting)
- [Out-of-Band Detection Server](#out-of-band-detection-server)
- [Multi-Target Bulk Scanning](#multi-target-bulk-scanning)
- [Tor System](#tor-system)
- [DDoS Safety Controls](#ddos-safety-controls)
- [Terminal Session Recording](#terminal-session-recording)
- [Command Reference](#command-reference)
  - [WAF & Firewall Detection](#waf--firewall-detection)
  - [Injection Modules](#injection-modules)
  - [Authentication & Session Modules](#authentication--session-modules)
  - [RCE · SSRF · LFI Modules](#rce--ssrf--lfi-modules)
  - [HTTP Smuggling](#http-smuggling)
  - [File & Upload Modules](#file--upload-modules)
  - [Reconnaissance](#reconnaissance)
  - [JavaScript & DOM Analysis](#javascript--dom-analysis)
  - [Traffic Abuse Modules](#traffic-abuse-modules)
  - [CVE Execution](#cve-execution)
  - [OOB Blind Detection](#oob-blind-detection)
  - [Multi-Layer DDoS Simulation](#multi-layer-ddos-simulation)
  - [Meta Commands](#meta-commands)
- [Payload Library](#payload-library)
- [WAF Signature Database](#waf-signature-database)
- [CVE Database](#cve-database)
- [Database Schema](#database-schema)
- [File Layout](#file-layout)
- [Interactive Shell](#interactive-shell)
- [Security Model](#security-model)
- [Self-Test](#self-test)
- [License & Ethics](#license--ethics)

---

## Core Capabilities

- **160+ WAF/CDN Signatures** — Cloudflare, Akamai, Imperva, Sucuri, F5, Fortinet, Radware, AWS, Azure, Google, Fastly, StackPath, Chinese WAFs (SafeLine, Yundun, Aliyun, Tencent), Russian (Qrator, DDoS-Guard), Japanese (Scutum), Swiss (Airlock, NevisProxy), and every major open-source WAF (ModSecurity, NAXSI, Wordfence, Barikode).
- **60+ Attack Categories** — SQLi, blind SQLi, XSS, DOM XSS, NoSQL, SSTI, XXE, SSRF, CMDi, LFI, LDAP, JWT, OAuth, GraphQL, deserialization, prototype pollution, Log4Shell, Spring4Shell, Shellshock, CRLF, HPP, CORS, upload bypass, SSI, format string, IDOR, mass assignment, subdomain takeover, DNS rebind, race conditions, WAF bypass, WAF crash, WAF admin discovery, WAF timeline, cache poisoning, session hijacking, header audit, TLS audit, H2C smuggle, CL.0 desync, HTTP/2 desync, WebSocket origin bypass, XXE→AWS IMDS, RL evasion, origin IP hunting, passive recon, active port scan, CVE intel, CVE execution, PHP2Shell analysis, WAF rule inference, JS recon, postMessage bypass, CSP bypass, SPA router bypass, SRI audit, service worker audit, DOM clobbering.
- **17 HTTP-Executable CVE Chains** — CVE-2024-4577 (PHP CGI), CVE-2019-19781 (Citrix), CVE-2021-21985 (vCenter), CVE-2021-44228 (Log4Shell), CVE-2021-26855 (ProxyLogon), CVE-2021-34473 (ProxyShell), CVE-2022-22965 (Spring4Shell), CVE-2022-26134 (Confluence OGNL), CVE-2022-40684 (FortiOS), CVE-2020-14882 (WebLogic), CVE-2023-4966 (Citrix Bleed), CVE-2024-3400 (PAN-OS), CVE-2023-34362 (MOVEit), CVE-2025-31324 (SAP), CVE-2025-4428 (Ivanti EPMM), CVE-2017-12617 (Tomcat PUT).
- **Hundreds of Curated Payloads** — DBMS-specific, WAF-bypass-encoded, encoding-mutated, and framework-targeted.
- **Multi-Layer DDoS Simulation** — L3 (latency/packet loss), L4 (TCP connect/reset), L7 (HTTP flood) with live ASCII dashboard.
- **OOB Callback Server** — Detects blind SSRF, XXE, and Log4Shell that don't reflect in-band.
- **Multi-Target Bulk Scanning** — Threaded parallel scanning with JSON export.
- **Terminal Session Recording** — Every byte of output auto-saved on exit as `.txt`, `.json`, `.xml`, and appended to `ALL_SESSIONS.*`.
- **Tor Integration** — Verify SOCKS5 reachability and exit-IP via check.torproject.org.
- **Zero External Dependencies** — Pure Python 3 standard library only.

---

## Installation

```bash
git clone https://github.com/sylhetyhackvenger/APEXORA
cd APEXORA 
python3 apexora.py

username: sylhetyhackvenger
pass: error808
```

Requirements: Python 3.8+. SQLite included with Python. No pip install needed.

---

Authentication & Scope

APEXORA enforces a two-layer access model:

1. Session token gate — username and password hashed with SHA-256, token persisted to ~/.APEXORA/.auth with 24-hour TTL.
2. Scope allowlist — every target must be present in ~/.APEXORA/scope.txt before any scan runs.

```bash
apexora scope --add example.com
apexora scope --add "*.example.com"
apexora scope --add 10.0.0.0/8
apexora scope --remove old.example.com
apexora scope --clear
apexora scope
```

Override for a single run with --force after accepting responsibility.

Optional HTTP Basic Authentication gate:

```bash
apexora basic-auth
```

---

Rate Limiting

The global rate limiter inserts a delay + jitter between every outbound HTTP request across all modules. This is critical for avoiding WAF rule triggers and rate-based blocking during reconnaissance and exploitation.

```bash
apexora rate --delay 0.5 --jitter 0.2
apexora rate
```

· delay — base seconds between requests (capped at 10s)
· jitter — random 0..jitter seconds added per request (capped at 5s)

Persisted in ~/.APEXORA/rate.json. Applies automatically to every fetch() call in every module.

---

Out-of-Band Detection Server

Many of the most impactful vulnerabilities — blind SSRF, XXE, Log4Shell, blind command injection — never reflect in the in-band response. APEXORA runs a built-in HTTP callback server that records every inbound request so you can prove exploitation.

```bash
apexora oob start --host 0.0.0.0 --port 8888
apexora oob status
apexora oob hits
apexora oob clear
apexora oob stop
```

Then run the OOB scanner:

```bash
apexora oob-blind example.com
```

The scanner sends OOB payloads (SSRF URL, XXE entity, JNDI LDAP, JNDI DNS) and waits for callbacks. Every interaction is logged to the oob_interactions table with source IP, method, path, headers, and token.

Use in a real network: bind to 0.0.0.0 and expose port 8888 (or a public tunnel like ngrok) so the target can reach back.

---

Multi-Target Bulk Scanning

Scan a list of targets in parallel:

```bash
echo "a.example.com" > targets.txt
echo "b.example.com" >> targets.txt
apexora bulk --category sqli --targets-file targets.txt --output results.json
```

· Loads targets (one per line, # comments skipped)
· Runs in a 10-worker thread pool
· Persists to bulk_runs table
· Optional JSON export via --output
· Scope checked per target (bypass with --force)

All categories supported: bulk --category <any-runner>.

---

Tor System

Run APEXORA through Tor to obscure source IP:

Terminal 1:

```bash
tor
# or: torsocks on
```

Terminal 2:

```bash
apexora tor start --host 127.0.0.1 --port 9050
apexora tor status
```

Status verifies the SOCKS5 proxy is reachable and queries check.torproject.org/api/ip through it to report the exit IP.

Then set environment before running scans:

```bash
export http_proxy=socks5://127.0.0.1:9050
export https_proxy=socks5://127.0.0.1:9050
apexora sqli example.com
```

---

DDoS Safety Controls

The DDoS simulator respects a safety limit by default:

```bash
apexora ddos-safety --mode status
apexora ddos-safety --mode off    # unlimited (use responsibly)
apexora ddos-safety --mode on     # re-enable
```

· ON: max duration 300s, max concurrency 500
· OFF: caps lifted to 99999 (unlimited attack mode)

Always requires target in scope. Always required before any ddos command runs.

---

Terminal Session Recording

Every byte written to stdout is captured. On tool exit (normal, SIGINT, exception, or save-all), the following are written to ~/.APEXORA/reports/:

· session_YYYYMMDD_HHMMSS.txt — raw ANSI text
· session_YYYYMMDD_HHMMSS.json — timestamped records
· session_YYYYMMDD_HHMMSS.xml — XML-escaped lines
· ALL_SESSIONS.txt — appended cumulative text
· ALL_SESSIONS.json — appended cumulative JSON

Manual dump:

```bash
apexora save-all
```

---

Command Reference

WAF & Firewall Detection

```bash
apexora detect-firewall/waf example.com
apexora waf-fingerprint example.com
apexora waf-timeline example.com
apexora waf-bypass example.com
apexora waf-break example.com
apexora waf-admin example.com
apexora waf-list cloudflare
apexora waf-list
```

detect-firewall/waf — first-level probe. Fetches the target, extracts server/cookie/body evidence, cross-references against all 160+ signatures, and prints every match with vendor, category, confidence, purpose description, and evidence. Records to scans table.

waf-fingerprint — active behavioral fingerprint. Sends safe probes (', ' OR 1=1--, <script>, ../../etc/passwd, ${7*7}) and detects status-code or body changes.

waf-timeline — sends an escalating payload timeline (' → ' OR → ' OR 1 → ' OR 1=1-- → ' UNION SELECT → ' AND SLEEP(5)--) and identifies the exact index where the WAF starts blocking.

waf-bypass — 60+ obfuscated SQLi payloads (comment injection, Unicode, encoding, case mutation). Reports any that reach the DB or bypass a baseline block.

waf-break — sends oversized/malformed payloads to trigger WAF crashes or regex backtracking DoS.

waf-admin — probes 30+ known WAF admin paths (Cloudflare internal, FortiWeb, Citrix ADC, ModSecurity, etc.).

waf-list — full offline signature browser with descriptions.

Injection Modules

```bash
apexora sqli example.com
apexora sqli-blind example.com
apexora xss example.com
apexora nosql example.com
apexora ssti example.com --framework jinja2-sandbox
apexora xxe example.com
apexora ldap example.com
apexora hpp example.com
apexora crlf example.com
apexora fmt example.com
```

sqli — dual-mode error-based and time-based SQL injection. Sends up to 60 payloads, detects DBMS error signatures (mysql_fetch, ora-01756, syntax error, PDOException, etc.), and confirms time-based delays >4500ms. Aborts after 8 WAF blocks.

sqli-blind — boolean and time-based blind probes. Detects delays >4500ms without a WAF trigger.

xss — 80+ reflected XSS vectors. Confirms payload reflection in the response body unencoded.

nosql — 50+ MongoDB operator payloads ($ne, $gt, $regex, $where) sent as JSON. Detects auth bypass by comparing baseline 401/403 to 200/201.

ssti — 50+ template injection vectors. Frameworks: jinja2-sandbox, twig, freemarker, webpy-0.76, litellm-1.82.4, generic.

xxe — 24 XML external entity payloads covering /etc/passwd, Windows win.ini, PHP filter, expect://, AWS IMDS, SSRF via entity.

ldap — 40+ LDAP filter injection payloads.

hpp — HTTP parameter pollution.

crlf — header injection via \r\n in redirect parameters.

fmt — printf/format string specifiers.

Authentication & Session Modules

```bash
apexora jwt example.com
apexora oauth example.com
apexora session example.com
apexora cors example.com
apexora graphql example.com
apexora deser example.com
apexora proto example.com
```

jwt — tests alg=none acceptance and kid traversal for JWT.

oauth — 12 redirect_uri bypass variants (evil.com, //evil.com, legit.com@evil.com, .evil.com suffix).

session — audits Set-Cookie for HttpOnly, Secure, SameSite.

cors — detects Access-Control-Allow-Origin reflection with Allow-Credentials: true.

graphql — probes /graphql and /api/graphql for introspection and __schema leakage.

deser — 4 languages of deserialization payloads (Java rO0AB..., PHP O:8:"stdClass", Python pickle, .NET AAEAAAD).

proto — prototype pollution via __proto__, constructor[prototype], JSON body forms.

RCE · SSRF · LFI Modules

```bash
apexora cmdi example.com
apexora ssrf example.com
apexora lfi example.com
apexora log4j example.com
apexora spring example.com
apexora shellshock example.com
apexora php2shell example.com
apexora chain-xxe-aws example.com
apexora rl-evade example.com
```

cmdi — 100+ OS command injection (; id, | id, $(id), ${IFS}id, %0A, sleep, DNS exfil). Confirms uid= or gid= in body.

ssrf — 50+ SSRF payloads (127.0.0.1, 169.254.169.254 IMDSv1, 0x7f.0.0.1, [::ffff:127.0.0.1], file://, gopher://, dict://). Confirms AccessKeyId or root: in body.

lfi — 45+ local file inclusion payloads for /etc/passwd, php://filter, data://, expect://, phar://, zip://.

log4j — Log4Shell via UA, X-Api-Version, X-Forwarded-For headers. 5 JNDI mutation variants.

spring — Spring4Shell class.module.* parameter injection.

shellshock — Bash function injection via UA/Referer/Cookie.

php2shell — reads X-Powered-By and flags vulnerable PHP versions (8.0–8.5 with UAF).

chain-xxe-aws — sends XXE to IMDSv1 and extracts AccessKeyId, SecretAccessKey, Token from response.

rl-evade — Q-learning over 30 episodes selecting best WAF-evasion mutation (plain, hex, comment, case, tautology).

HTTP Smuggling

```bash
apexora h2c example.com
apexora cl0 example.com
apexora http2 example.com
apexora ws example.com
```

h2c — H2C cleartext upgrade probe.

cl0 — CL.0 desync via Content-Length: 0 + Transfer-Encoding: chunked.

http2 — HTTP/2 desync via raw PRI preface, SETTINGS, RST_STREAM floods.

ws — WebSocket cross-origin handshake.

File & Upload Modules

```bash
apexora upload example.com
apexora ssi example.com
apexora cache-inject example.com
```

upload — 30+ extension bypasses (shell.php, shell.php.jpg, shell.pHp, shell.php%00.jpg, shell.phtml, shell.phar, .htaccess, shell.php::$DATA).

ssi — SSI directives <!--#exec cmd="id" -->.

cache-inject — cache poisoning via path split + Accept/X-Forwarded-Host/Origin.

Reconnaissance

```bash
apexora recon-passive example.com
apexora recon-active example.com
apexora subdomain-enum example.com
apexora subdomain-takeover example.com
apexora dns-rebind example.com
apexora origin example.com
apexora headers example.com
apexora tls example.com
apexora cve-intel example.com
apexora rule-steal example.com
```

recon-passive — probes /.env, /.git/config, /phpinfo.php, /server-status, /.DS_Store, /backup.zip.

recon-active — TCP connect on 17 ports (21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017).

subdomain-enum — wordlist of 28 common subdomains (admin, dev, staging, api, mail, vpn, etc.).

subdomain-takeover — dangling CNAME check against Heroku, GitHub Pages, etc.

dns-rebind — checks nip.io and localtest.me for wildcard loopback.

origin — hunts for origin IP behind CDN by subdomain resolution + Host: header override.

headers — checks HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy.

tls — negotiates TLS and flags TLSv1/1.1, RC4/DES/MD5.

cve-intel — signature-only probe across 24 CVEs.

rule-steal — infers WAF rule coverage by testing 6 features (', '--, ' UNION, ' SLEEP, 0x41, CONCAT).

JavaScript & DOM Analysis

```bash
apexora js-recon example.com
apexora dom-xss example.com
apexora postmessage example.com
apexora csp example.com
apexora router example.com
apexora sri example.com
apexora service-worker example.com
apexora dom-clobbering example.com
```

js-recon — extracts script src URLs and inline JS, matches DOM sinks (innerHTML, outerHTML, document.write, eval, insertAdjacentHTML) and sources (location.hash, document.URL, postMessage, etc.), checks CSP.

dom-xss — reflects <img src=x onerror=alert(1)> and javascript:alert(1) in fragment responses.

postmessage — detects addEventListener('message') without event.origin filter.

csp — flags missing CSP, unsafe-inline, unsafe-eval, JSONP bypass hosts.

router — detects React Router, Vue Router, Angular Router, SvelteKit; probes /admin, /dashboard, /settings for unauth access.

sri — flags external scripts missing integrity= attribute.

service-worker — detects navigator.serviceWorker presence.

dom-clobbering — reflects <a id="config">, <form id="config">, <img name="getElementById">.

Traffic Abuse Modules

```bash
apexora race example.com
apexora mass-assign example.com
apexora idor example.com
```

race — 20 parallel POSTs on redeem endpoint; classifies TOCTOU if >1 success.

mass-assign — JSON with "admin":true, "role":"admin", "is_admin":true to detect privilege escalation.

idor — probes /api/user/1, /api/user/2, etc. for sensitive data leakage (email, password, token, api_key).

CVE Execution

```bash
apexora cve-exec example.com
apexora cve-exec example.com --id CVE-2021-44228
apexora cve example.com
apexora cve "2021"
apexora cve
```

cve-exec — runs all 17 HTTP-executable CVE chains. Each returns exploited: true/false with evidence.

cve — offline CVE database search. Prints ✓EXEC for HTTP-executable, probe for protocol-only.

OOB Blind Detection

```bash
apexora oob start --host 0.0.0.0 --port 8888
apexora oob-blind example.com
apexora oob hits
apexora oob clear
apexora oob stop
```

Sends SSRF URL, XXE entity, JNDI LDAP, JNDI DNS payloads pointing to the OOB server. Waits 1s. Reports any callbacks as CRITICAL blind vulnerabilities.

Multi-Layer DDoS Simulation

```bash
apexora ddos example.com
apexora ddos example.com --modules l3,l4,l7 --duration 30 --concurrency 100
apexora ddos example.com --modules l7
apexora ddos-safety --mode status
```

L3 — 10 TCP connect attempts to port 80, records RTT distribution and packet loss, classifies congestion.

L4 — concurrent TCP connect to 6 ports, tracks success/reset/timeout, flags connection-table exhaustion.

L7 — 4× concurrency threaded HTTP requests to /, /api/health, /api/v1/status, /robots.txt, /, with cache-buster query. Reports availability %, median/p95/p99 latency, status distribution.

ASCII Dashboard — live progress bar for L7 availability, L3 avg RTT/packet loss, L4 attempts/success rate, HTTP status distribution chart, and final classification: HEALTHY, DEGRADED, RATE_LIMITED, PARTIALLY_UNAVAILABLE, UNAVAILABLE, INCONCLUSIVE.

Meta Commands

```bash
apexora categories
apexora payloads
apexora payloads --category sqli
apexora payloads --category ssti
apexora waf-list
apexora waf-list cloudflare
apexora cve
apexora cve "CVE-2021"
apexora history --limit 20
apexora health
apexora stats
apexora version
apexora scope
apexora waf-rules --output rules.conf
apexora php2shell-rules --output php2shell.rules
apexora list-modules
apexora shell
apexora logout
apexora save-all
apexora --self-test
```

---

Payload Library

Every category contains 5–60 payloads tuned for real-world vulnerability confirmation:

Category Count Coverage
SQLi 260+ MySQL, MSSQL, Oracle, PostgreSQL, SQLite, WAF bypass
SQLi Blind 130+ boolean + time-based
XSS 90+ HTML, SVG, iframe, body, details, math, DOM clobbering
NoSQL 55+ MongoDB $ne, $gt, $regex, $where, $comment
SSTI 55+ Jinja2, Twig, Freemarker, Web.py, LiteLLM, generic
XXE 24 file://, php://filter, expect://, IMDS, OOB
SSRF 60+ loopback, private, IMDS, metadata.google, file://, dict://, gopher://
CMDi 100+ semicolon, pipe, backtick, $(), ${IFS}, encoding
LFI 45+ traversal, encoded, php://filter, data://, phar://
LDAP 45+ *)(uid=*, `*)(
JWT 12 alg none, kid traversal
OAuth 12 redirect_uri bypass
GraphQL 12 introspection, mutation
Deser 4 Java, PHP, Python, .NET
Proto 12 __proto__, constructor[prototype]
Log4Shell 12 JNDI ldap/rmi/dns, case mutation
Spring4Shell 3 class.module.*
Shellshock 9 bash function
CRLF 12 \r\n, %0d%0a
HPP 12 duplicate param
CORS 12 evil.com, null, legit.com@evil.com
Upload 30+ php, php.jpg, pHp, %00, phtml, phar, htaccess
SSI 9 #exec, #include, #echo
FMT 16 %x, %s, %n, %99999999d
IDOR 18 sequential IDs
Mass Assign 12 role, is_admin, verified
Subdomain 28 admin, dev, staging, api, mail, vpn, etc.
WAF Bypass 60+ encoding, case, comment
WAF Break 18 oversized, null-byte, chunked
WAF Admin 30+ FortiWeb, Citrix, ModSec
WAF Timeline 24 escalating
Session 15 JWT, PHPSESSID, JSESSIONID
DOM XSS 15 img, svg, iframe, body, details
Angular 9 sandbox escape
Vue 6 template injection
PostMessage 6 window.parent, window.opener
WebSocket 12 SQLi, XSS, SSRF
DOM Clobber 9 config, getElementById

---

WAF Signature Database

Every WAF entry includes headers, cookies, body markers, vendor, category, confidence, and a plain-English purpose description. Over 160 signatures across:

· Cloud WAFs: Cloudflare, AWS WAF/Shield/ELB, Azure App Gateway/Front Door, Google Cloud Armor, Oracle Cloud, Huawei, Alibaba, Tencent, Baidu
· Enterprise: F5 BIG-IP ASM/APM/LTM/Silverline/Trafficshield, Fortinet FortiWeb/FortiGate/FortiGuard, Imperva SecureSphere/Incapsula, Citrix NetScaler, Radware AppWall, Barracuda, Cisco ACE, IBM DataPower, Palo Alto, WatchGuard, Sophos, Zscaler
· CDN+WAF: Akamai + Kona, Fastly, Sucuri CloudProxy, StackPath, Edgecast, MaxCDN, KeyCDN, CacheFly, Beluga
· Bot/Anti-automation: Distil, PerimeterX, Anubis, CrawlProtect, BitNinja, Imunify360
· Open-source: ModSecurity, NAXSI, Wordfence, SafeLine, Barikode, NinjaFirewall, BulletProof, Malcare, WPMU DEV
· Chinese: 360 PanYun, 360 WangZhanBao, Safedog, Yundun, Yunsuo, XuanWuDun, UEWaf, Jiasule, Anquanbao, Chuang Yu, KS-WAF, WebRay, NSFocus, Puhui, SecKing, YXLink
· Russian: DDoS-Guard, Qrator
· Japanese: Scutum
· Swiss: Airlock, NevisProxy
· Server fingerprints: Apache, Nginx, IIS, LiteSpeed, Caddy, HAProxy, Envoy, Kong, Traefik, OpenResty

---

CVE Database

24 entries, each with CVE ID, product, type, pre-auth status, RCE flag, CVSS, PoC availability, affected versions, KEV flag, protocol, HTTP probe path, detect marker, and notes.

CVE Product CVSS Type
CVE-2024-4577 PHP CGI Windows 9.8 arg injection
CVE-2019-19781 Citrix ADC 9.8 traversal
CVE-2021-21985 VMware vCenter 9.8 RCE
CVE-2021-22005 VMware vCenter 9.8 file upload
CVE-2021-44228 Log4j 10.0 JNDI
CVE-2021-26855 Exchange 9.8 SSRF (ProxyLogon)
CVE-2021-34473 Exchange 9.8 path confusion (ProxyShell)
CVE-2022-22965 Spring 9.8 classloader
CVE-2022-26134 Confluence 9.8 OGNL
CVE-2023-34362 MOVEit 9.8 SQLi
CVE-2024-3400 PAN-OS 10.0 CMDi
CVE-2022-40684 FortiOS 9.8 auth bypass
CVE-2020-14882 WebLogic 9.8 RCE
CVE-2023-4966 Citrix Bleed 9.4 session leak
CVE-2025-31324 SAP NetWeaver 10.0 file upload
CVE-2025-4428 Ivanti EPMM 9.8 RCE
CVE-2017-12617 Tomcat 8.1 JSP upload
CVE-2023-46604 ActiveMQ 10.0 deserialization
CVE-2024-21762 FortiOS SSL-VPN 9.8 OOB write
CVE-2022-42475 FortiOS 9.8 heap overflow
CVE-2025-2250 Chrome V8 8.8 type confusion
CVE-2021-4034 Polkit 7.8 LPE
CVE-2020-1472 Zerologon 10.0 auth bypass
CVE-2021-34527 PrintNightmare 8.8 RCE
CVE-2019-0708 BlueKeep 9.8 RCE
CVE-2023-3824 PHP phar 9.8 buffer overflow

---

Database Schema

SQLite-backed at ~/.APEXORA/db/apexora.sqlite:

· scans — WAF fingerprint runs (id, target_url, ip, status, server, http_status, response_ms, body_size, detected_json, headers_json, created_at)
· vuln_tests — vulnerability module runs (id, target_url, category, payload_count, findings_count, criticality, findings_json, duration_ms, created_at)
· ddos_runs — DDoS simulation runs (id, target_url, modules, duration_s, intensity, availability_pct, classification, telemetry_json, created_at)
· oob_interactions — OOB callbacks (id, target_url, category, token, source_ip, headers_json, created_at)
· bulk_runs — bulk scans (id, category, targets_json, results_json, duration_ms, created_at)

---

File Layout

```
~/.APEXORA/
├── .auth                 # session token (chmod 600)
├── scope.txt             # scope allowlist
├── rate.json             # rate limiter config
├── oob.json              # OOB server config
├── tor.json              # Tor config
├── bulk_targets.txt      # default bulk target list
├── useragent.txt         # extra UA strings (optional)
├── db/
│   └── apexora.sqlite    # history database
└── reports/
    ├── session_YYYYMMDD_HHMMSS.txt
    ├── session_YYYYMMDD_HHMMSS.json
    ├── session_YYYYMMDD_HHMMSS.xml
    ├── ALL_SESSIONS.txt
    └── ALL_SESSIONS.json
```

---

Interactive Shell

```bash
apexora
```

Drops into a REPL with a persistent scope-aware prompt:

```
apexora> scope --add example.com
apexora> detect-firewall/waf example.com
apexora> sqli example.com
apexora> oob start
apexora> oob-blind example.com
apexora> bulk --category xss --targets-file targets.txt
apexora> help
apexora> exit
```

Meta commands (categories, version, health, stats, scope, payloads, cve, waf-list, history, waf-rules, php2shell-rules, oob, rate, tor, bulk, ddos-safety, save-all, basic-auth, logout) work directly. Attack commands take a target as first argument.

---

Security Model

· Two-factor access: SHA-256 hashed credentials + 24h session token
· Scope enforcement: every target must be in allowlist (per-target in bulk mode)
· Rate limiting: global cross-module delay + jitter to avoid WAF triggers
· Abort safety: modules abort after 8 consecutive WAF blocks
· Connection cleanup: all sockets closed via finally
· No shell execution: only outbound HTTP/TCP/DNS — no os.system, no subprocess
· DDoS safety limit: caps duration at 300s and concurrency at 500 unless explicitly disabled
· Terminal recording: every byte logged to reports/ on exit
· Audit trail: every scan/test/ddos/oob/bulk persisted to SQLite

---

Self-Test

```bash
apexora --self-test
```

Prints:

· Python version, TTY detection
· Every file path and whether it exists
· Payload counts per category and total
· WAF signature count, description coverage check
· CVE database size, HTTP-executable vs probe-only
· Attack runner count
· DB init status
· Auth hash verification
· Scope patterns
· DDoS safety state
· Rate limiter state
· OOB server state
· Tor state
· Bulk mode state
· Terminal recorder state

---

License & Ethics

AUTHORIZED TESTING AND EDUCATIONAL RESEARCH ONLY.

APEXORA is a security analysis framework. Use only against systems you own or have written permission to test. Unauthorized use violates computer fraud laws including CFAA (US), UK Computer Misuse Act, and local equivalents.

The author assumes no liability for misuse. By proceeding you accept full responsibility. All actions are logged. Scope must be declared before testing.

Author: SYLHETYHACKVENGER (THE-ERROR808)

---

APEXORA — Multi-Layer Firewall Analysis · Offensive & Defensive Security Intelligence · Attack-Surface Discovery & Advanced Penetration Testing Framework

```
