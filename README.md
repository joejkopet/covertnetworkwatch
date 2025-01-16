# Covert Network Watch
![image](https://github.com/joejkopet/covertnetworkwatch/blob/main/logo.png)


**Covert Network Watch** is a passive network reconnaissance tool designed to monitor network interfaces and display various network-related information. This tool provides detailed insights into different aspects of the network, helping network security professionals to analyze and understand their network environment.

Many network devices come with default configurations that broadcast a significant amount of information. This can include details from protocols such as CDP (Cisco Discovery Protocol), various routing protocols, and more. While these defaults can be useful for network management and troubleshooting, they also pose security risks by exposing sensitive information that can be exploited by attackers.

## Features

- **Graphical User Interface (GUI)**: Built using `tkinter` and `ttkbootstrap` for a modern look.
- **Network Interface Selection**: Dropdown menu to select the network interface and display MAC and IPv4 addresses.
- **Network Reconnaissance**: Uses `tshark` to capture network traffic and extract information.
- **Information Display**: Text boxes with scrollbars to display various network details such as:
  
  - Native VLAN
  - Network device names
  - Network device models
  - Network device IOS versions
  - Network device management IPs
  - OSPF neighbors
  - EIGRP neighbors
  - STP root bridge
    
- **Progress Bar**: Indicates the progress of the network reconnaissance.

## Dependencies

- `tkinter`
- `ttkbootstrap`
- `psutil`
- `socket`
- `subprocess`
- `threading`
- `time`
- `os`
- `tshark` (System Package)


## Usage

1. Run the main script:
   ```bash
   python covert_network_watch.py
   ```
2. Select the network interface from the dropdown menu.
3. Click on "Start Recon" to begin the network reconnaissance.
4. View the extracted network information in the respective text boxes.

## Screenshot

![image](https://github.com/joejkopet/covertnetworkwatch/blob/main/screenshot.png)">

## Security Implications of Network Information

### Native VLAN
- **Security Concern**: Misconfigured native VLANs can lead to VLAN hopping attacks, where an attacker sends packets to different VLANs, potentially gaining unauthorized access to network segments.

### Network Device Names
- **Security Concern**: Revealing device names provides attackers with valuable information about the network infrastructure, making it easier to target specific devices.

### Network Device Models
- **Security Concern**: Knowing the models of network devices helps attackers identify vulnerabilities specific to those models, increasing the risk of targeted attacks.

### Network Device IOS Versions
- **Security Concern**: Outdated IOS versions may have known vulnerabilities that attackers can exploit. Keeping IOS versions up-to-date is crucial for network security.

### Network Device Management IPs
- **Security Concern**: Exposing management IPs allows attackers to target the management interfaces of network devices, potentially gaining control over them.

### OSPF Neighbors
- **Security Concern**: OSPF (Open Shortest Path First) neighbors can be targeted for OSPF spoofing attacks, where an attacker injects malicious routing information into the network.

### EIGRP Neighbors
- **Security Concern**: EIGRP (Enhanced Interior Gateway Routing Protocol) neighbors can be targeted for EIGRP spoofing attacks, similar to OSPF, leading to routing disruptions.

### STP Root Bridge
- **Security Concern**: Misconfigured STP (Spanning Tree Protocol) root bridges can lead to STP manipulation attacks, where an attacker changes the network topology to create loops or disrupt network traffic.
