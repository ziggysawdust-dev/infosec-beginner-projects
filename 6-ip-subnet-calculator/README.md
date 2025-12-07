# IP Subnet Calculator with Visual Breakdown

## Overview
An interactive Python tool that calculates and visualizes IP subnet information with byte-level breakdown to help understand subnetting, CIDR notation, and network addressing.

## Learning Outcomes
- IP address structure (32 bits = 4 octets)
- Binary representation of IP addresses
- Subnet masks and CIDR notation
- Network vs. Host portions
- IP address classes (A, B, C, D, E)
- Public vs. Private networks
- Network calculations (broadcast, first/last host)
- Subnetting fundamentals

## Features

### Core Calculations
- **Binary Breakdown**: Visual representation of IP addresses in binary
- **Subnet Mask Display**: Color-coded network vs. host bits
- **Network Information**: Network address, broadcast address, host range
- **Host Validation**: Check if an IP belongs to a subnet
- **IP Classification**: Identify IP class and network type

### Visual Elements
- Color-coded binary (blue = network, green = host)
- Octet-by-octet breakdown with decimal and binary
- Host range visualization
- Common subnet mask reference

## Usage

### Basic Usage
```bash
python ip_calculator.py
```

### Examples

**Example 1: Class C Network (192.168.1.0/24)**
```
Input: 192.168.1.0/24

Output:
- 256 total addresses
- Network: 192.168.1.0
- Broadcast: 192.168.1.255
- First host: 192.168.1.1
- Last host: 192.168.1.254
- Usable hosts: 254
```

**Example 2: Subnetted Class C (192.168.1.0/26)**
```
Input: 192.168.1.0/26

Output:
- 64 total addresses
- Network: 192.168.1.0
- Broadcast: 192.168.1.63
- First host: 192.168.1.1
- Last host: 192.168.1.62
- Usable hosts: 62
```

## Understanding the Visualization

### Binary Breakdown Format
```
IP Address Binary:    11000000 10101000 00000001 00000000
Subnet Mask Binary:   11111111 11111111 11111111 00000000
                      ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^
                      Network  Network  Network  Host
```

### Color Coding
- **Blue (■)**: Network portion (CIDR bits)
- **Green (■)**: Host portion (remaining bits)

### Octet Breakdown Example
```
Octet 1: 192 = 11000000  (Network)
Octet 2: 168 = 10101000  (Network)
Octet 3: 1   = 00000001  (Network)
Octet 4: 0   = 00000000  (Host)
```

## IP Address Structure

### 32-Bit Layout
```
IP Address = 32 bits = 4 octets × 8 bits

192.168.1.0 in binary:
11000000 . 10101000 . 00000001 . 00000000
^^^^^^^^   ^^^^^^^^   ^^^^^^^^   ^^^^^^^^
  192        168         1         0
```

## CIDR Notation Explained

CIDR = Classless Inter-Domain Routing

Format: `IP_ADDRESS/PREFIX_LENGTH`

- `/24` = 24 network bits + 8 host bits
- `/25` = 25 network bits + 7 host bits
- `/16` = 16 network bits + 16 host bits

### Common CIDR Values
| CIDR | Subnet Mask | Addresses | Usable Hosts |
|------|-------------|-----------|--------------|
| /8  | 255.0.0.0 | 16,777,216 | 16,777,214 |
| /16 | 255.255.0.0 | 65,536 | 65,534 |
| /24 | 255.255.255.0 | 256 | 254 |
| /25 | 255.255.255.128 | 128 | 126 |
| /26 | 255.255.255.192 | 64 | 62 |
| /27 | 255.255.255.224 | 32 | 30 |
| /28 | 255.255.255.240 | 16 | 14 |
| /30 | 255.255.255.252 | 4 | 2 |

## IP Address Classes

### Traditional Classification
```
Class A:  1.0.0.0 to 126.255.255.255    (First octet: 1-126)
  └─ Default mask: /8

Class B:  128.0.0.0 to 191.255.255.255  (First octet: 128-191)
  └─ Default mask: /16

Class C:  192.0.0.0 to 223.255.255.255  (First octet: 192-223)
  └─ Default mask: /24

Class D:  224.0.0.0 to 239.255.255.255  (Multicast)
  └─ Special use

Class E:  240.0.0.0 to 255.255.255.255  (Reserved)
  └─ Special use
```

## Private IP Ranges (RFC 1918)

These addresses are reserved for private use and not routable on the internet:

```
Class A Private:  10.0.0.0/8
  └─ Range: 10.0.0.0 to 10.255.255.255

Class B Private:  172.16.0.0/12
  └─ Range: 172.16.0.0 to 172.31.255.255

Class C Private:  192.168.0.0/16
  └─ Range: 192.168.0.0 to 192.168.255.255
```

## Network Calculations Explained

### Network Address
- All host bits set to 0
- Used to identify the subnet
- Example: 192.168.1.0/24

### Broadcast Address
- All host bits set to 1
- Used to send messages to all hosts
- Example: 192.168.1.255/24

### First Host Address
- Network address + 1
- First usable address
- Example: 192.168.1.1/24

### Last Host Address
- Broadcast address - 1
- Last usable address
- Example: 192.168.1.254/24

## Subnetting Examples

### Example 1: Dividing a /24 into /25 subnets
```
Original: 192.168.1.0/24 (256 addresses)
Split into 2 subnets:

Subnet 1: 192.168.1.0/25
  ├─ Network: 192.168.1.0
  ├─ Broadcast: 192.168.1.127
  └─ Hosts: 192.168.1.1 to 192.168.1.126

Subnet 2: 192.168.1.128/25
  ├─ Network: 192.168.1.128
  ├─ Broadcast: 192.168.1.255
  └─ Hosts: 192.168.1.129 to 192.168.1.254
```

### Example 2: Dividing a /24 into /26 subnets
```
Original: 192.168.1.0/24 (256 addresses)
Split into 4 subnets:

Subnet 1: 192.168.1.0/26   (0-63)
Subnet 2: 192.168.1.64/26  (64-127)
Subnet 3: 192.168.1.128/26 (128-191)
Subnet 4: 192.168.1.192/26 (192-255)
```

## How Bits Work in Subnetting

### Understanding Binary Math
```
1 bit can represent:    2 values (0 or 1)
2 bits can represent:   4 values (00, 01, 10, 11)
3 bits can represent:   8 values
4 bits can represent:   16 values
8 bits can represent:   256 values
```

### Calculating Number of Addresses
```
Formula: 2^(host_bits)

Example: /24 network
  Host bits = 32 - 24 = 8
  Total addresses = 2^8 = 256
  Usable hosts = 256 - 2 = 254

Example: /25 network
  Host bits = 32 - 25 = 7
  Total addresses = 2^7 = 128
  Usable hosts = 128 - 2 = 126
```

## Practical Use Cases

### Home Network
```
Typical setup: 192.168.1.0/24
- Network: 192.168.1.0
- Hosts: 192.168.1.1 to 192.168.1.254
- Broadcast: 192.168.1.255
```

### Small Office Network
```
Multiple departments: 192.168.0.0/22
Subnetted into /25 networks:
- Network A: 192.168.0.0/25
- Network B: 192.168.0.128/25
- Network C: 192.168.1.0/25
- Network D: 192.168.1.128/25
```

### Data Center
```
Large deployment: 10.0.0.0/8
Subnetted into smaller /24 networks:
- Web servers: 10.1.0.0/24
- Database: 10.2.0.0/24
- Storage: 10.3.0.0/24
```

## Special Addresses

### Reserved Ranges
```
0.0.0.0/8           This network
10.0.0.0/8          Private network (RFC 1918)
127.0.0.0/8         Loopback
169.254.0.0/16      Link-local
172.16.0.0/12       Private network (RFC 1918)
192.168.0.0/16      Private network (RFC 1918)
224.0.0.0/4         Multicast
240.0.0.0/4         Reserved for future use
255.255.255.255/32  Broadcast
```

## Interview Questions & Answers

**Q: What's the difference between /24 and /25?**
A: /24 has 8 host bits (256 addresses), /25 has 7 host bits (128 addresses). /25 provides finer-grained subnetting.

**Q: Why do we use CIDR notation?**
A: CIDR is simpler than traditional subnet masks and allows more flexible network sizing than Class-based addressing.

**Q: How many usable hosts in a /28 network?**
A: 2^(32-28) - 2 = 2^4 - 2 = 16 - 2 = 14 usable hosts.

**Q: What's a broadcast address?**
A: An address with all host bits set to 1. Packets sent to this address are delivered to all hosts in the subnet.

## Next Steps

1. **Understand subnetting** - Practice calculating networks manually
2. **Memorize common masks** - /24, /16, /8 are most common
3. **Hands-on practice** - Use this tool to verify your calculations
4. **Advanced topics** - VLSM (Variable Length Subnet Mask), IPv6, routing

## Real-World Applications

- **Network Planning**: Designing efficient IP schemes
- **Device Configuration**: Setting IP addresses and gateways
- **Firewall Rules**: Understanding network ranges for ACLs
- **Routing**: Understanding route aggregation
- **Troubleshooting**: Identifying network boundaries

## Common Mistakes to Avoid

- Forgetting about network and broadcast addresses
- Using /31 or /32 without understanding special cases
- Confusing network order with host order in binary
- Not accounting for 2 reserved addresses (network and broadcast)

## Further Learning

- Practice with different CIDR notations
- Learn about IPv6 and its much larger address space
- Study VLSM (Variable Length Subnet Masking)
- Explore network design patterns
- Study routing protocols that use CIDR

---

## Security Notes

Understanding IP addressing is crucial for:
- Network segmentation (security boundaries)
- Firewall rules (which networks to allow/block)
- VPN configuration (network overlap detection)
- Access control lists (ACLs)
- Network isolation and defense in depth

Good subnetting design is a cornerstone of network security! 🔒
