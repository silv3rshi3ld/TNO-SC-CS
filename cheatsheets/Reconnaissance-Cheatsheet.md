# StealthCup 2025: Reconnaissance Cheatsheet

This cheatsheet focuses on reconnaissance techniques optimized for stealth, minimizing the risk of triggering alerts from IDS, SIEM, and EDR solutions within the StealthCup environment.

**Primary Goal**: Gather information about the target network (`10.0.x.0/24`) without being detected.

## 1. Passive Reconnaissance (Zero Noise)

These techniques involve listening only and generate no network traffic from your Kali box.

- **Network Sniffing**: Capture traffic on the local segment to identify hosts, services, and communication patterns.
  - **Tools**: `tcpdump`, `wireshark` (tshark CLI)
  - **Example (`tcpdump`)**:
    ```bash
    # Capture traffic on eth0, don't resolve names (-n), don't use promiscuous mode initially
    sudo tcpdump -i eth0 -n -p not arp and not icmp
    # Filter for specific protocols (e.g., LDAP, SMB)
    sudo tcpdump -i eth0 -n -p 'port 389 or port 139 or port 445'
    ```
  - **Evasion Tip**: Avoid promiscuous mode (`-p`) initially if possible, as it can sometimes be detected. Analyze captured PCAPs offline.

- **Analyze Existing Data**: Check the Kali box for any pre-existing data, logs, or configuration files left by "Danilo".
  - **Commands**: `history`, `ls -la /home /tmp /var/log`, `find / -type f -mtime -7 2>/dev/null`

## 2. Low-Noise Active Reconnaissance

These techniques involve sending traffic but are designed to be less intrusive than standard scans.

- **Targeted Port Scanning (Known Services)**: Instead of scanning all ports, focus on common enterprise/OT ports.
  - **Tools**: `nmap`
  - **Example (`nmap` - Slow, specific ports)**:
    ```bash
    # Scan specific common ports with slow timing, no ping, no DNS resolution
    nmap -sS -T2 --max-retries 1 --scan-delay 1s -p 21,22,23,25,53,80,110,135,139,443,445,1433,1521,3306,3389,5900,5985,5986,47808 -Pn -n <target_IP>
    # Use decoy scanning (-D) if necessary, but can be noisy if overused
    # nmap -sS -T2 -D RND:5 <target_IP>
    ```
  - **Evasion Tip**: Use `-sS` (SYN scan) as it's often less logged than connect scans (`-sT`). Avoid OS detection (`-O`) and version scanning (`-sV`) initially as they are noisy. Use `-Pn` to skip host discovery if you already know the host is up.

- **Service Banner Grabbing (Manual)**: Connect manually to identified open ports to grab banners.
  - **Tools**: `nc` (netcat), `telnet`
  - **Example (`nc`)**:
    ```bash
    nc -nv <target_IP> <port>
    # Example for HTTP
    echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc -nv <target_IP> 80
    ```
  - **Evasion Tip**: Mimic legitimate client behavior. Don't probe too many ports rapidly from the same source IP.

- **DNS Enumeration (Internal)**: Query internal DNS servers if identified.
  - **Tools**: `dig`, `nslookup`
  - **Example (`dig` - Zone Transfer Attempt)**:
    ```bash
    dig axfr @<dns_server_ip> <domain_name>
    ```
  - **Evasion Tip**: Zone transfers are often logged/alerted. Prefer targeted queries for specific hostnames if possible.

- **SMB Enumeration (Careful)**: Enumerate SMB shares and sessions cautiously.
  - **Tools**: `smbclient`, `smbmap`, `enum4linux-ng`
  - **Example (`smbclient` - List Shares Anonymously)**:
    ```bash
    smbclient -L \\\\<target_IP> -N
    ```
  - **Example (`smbmap` - Null Session)**:
    ```bash
    smbmap -H <target_IP> -u '' -p ''
    ```
  - **Evasion Tip**: Null sessions and anonymous share listing are frequently monitored. Perform these actions sparingly and during expected "business hours" if possible. Avoid tools that perform overly aggressive enumeration.

## 3. Host Discovery (Stealthy Alternatives)

Standard ICMP/ARP scans can be noisy.

- **ARP Scan (Local Subnet)**: Less likely to traverse firewalls but good for local discovery.
  - **Tools**: `arp-scan`, `nmap -PR`
  - **Example (`arp-scan`)**:
    ```bash
    sudo arp-scan --localnet
    ```
  - **Evasion Tip**: ARP scans are generally less monitored than ICMP scans within the local subnet.

- **Targeted TCP/UDP Probes**: Send probes to common ports on potential hosts instead of ICMP.
  - **Tools**: `nmap -PS<portlist>`, `nmap -PA<portlist>`, `nmap -PU<portlist>`
  - **Example (`nmap` - SYN to port 80)**:
    ```bash
    nmap -PS80 -T2 --scan-delay 1s -Pn -n <target_range>
    ```
  - **Evasion Tip**: Probing common ports like 80 (TCP) or 53 (UDP) might appear more legitimate than ICMP echo requests.

## General Evasion Tips for Reconnaissance

- **Timing**: Use slow scanning profiles (`-T2`, `--scan-delay`) to avoid rate-based detection.
- **Targeting**: Scan specific IPs or small ranges rather than the entire subnet at once.
- **Source IP**: Your Kali box is the initial source. Be mindful of actions originating from it.
- **Protocols**: Prefer scans/probes using common protocols (TCP 80, 443, UDP 53) where possible.
- **Correlation**: Avoid performing multiple noisy actions in quick succession. Space out activities.
- **Analyze Traffic**: Before active scanning, passively listen to understand baseline traffic patterns and identify potential targets/services.

Remember to cross-reference findings with the [Alert Evasion Cheatsheet](Alert-Evasion-Cheatsheet.md) and the [Scoring System Cheatsheet](Scoring-System-Cheatsheet.md) to estimate the potential alert cost of each action.