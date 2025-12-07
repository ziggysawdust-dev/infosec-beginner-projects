"""
IP Subnet Calculator with Visual Byte Breakdown
Learn about IP addressing, subnetting, and network calculations.

Learning concepts:
- IP address structure (32 bits)
- Binary representation
- Subnet masks and CIDR notation
- Network address calculation
- Broadcast address calculation
- Host range calculation
"""

import sys
from typing import Tuple, List
import ipaddress


class IPCalculator:
    """Calculate and visualize IP subnet information."""
    
    def __init__(self, ip_with_mask: str):
        """
        Initialize calculator with IP/CIDR notation.
        
        Args:
            ip_with_mask: IP address with CIDR (e.g., "192.168.1.0/24")
        """
        try:
            self.network = ipaddress.ip_network(ip_with_mask, strict=False)
            self.ip = self.network.network_address
            self.subnet_mask = self.network.netmask
            self.cidr = self.network.prefixlen
        except ValueError as e:
            print(f"❌ Invalid IP/CIDR: {e}")
            sys.exit(1)
    
    def get_binary_breakdown(self, ip_addr) -> str:
        """Get binary representation of IP address with visual grouping."""
        # Convert IP to 32-bit binary
        ip_int = int(ip_addr)
        binary = format(ip_int, '032b')
        
        # Split into 4 octets (8 bits each)
        octets = [binary[i:i+8] for i in range(0, 32, 8)]
        
        # Color the network vs host portions
        network_bits = self.cidr
        network_binary = []
        host_binary = []
        
        bit_count = 0
        for octet in octets:
            octet_binary = ""
            for bit in octet:
                if bit_count < network_bits:
                    # Network portion (blue)
                    octet_binary += f"\033[94m{bit}\033[0m"
                else:
                    # Host portion (green)
                    octet_binary += f"\033[92m{bit}\033[0m"
                bit_count += 1
            network_binary.append(octet_binary)
        
        return " ".join(network_binary)
    
    def get_octet_breakdown(self, ip_addr) -> str:
        """Show IP address as decimal octets with binary equivalents."""
        octets = [int(x) for x in str(ip_addr).split('.')]
        breakdown = ""
        
        for i, octet in enumerate(octets):
            binary = format(octet, '08b')
            
            # Color based on network/host
            if i * 8 < self.cidr:
                # Network octet (partially or fully)
                color = "\033[94m"  # Blue
                label = "Network"
            else:
                # Host octet
                color = "\033[92m"  # Green
                label = "Host"
            
            breakdown += f"  Octet {i+1}: {color}{octet:3d}\033[0m = {binary}  ({label})\n"
        
        return breakdown
    
    def visualize_subnet_mask(self) -> str:
        """Visualize the subnet mask with network/host boundary."""
        mask_int = int(self.subnet_mask)
        binary = format(mask_int, '032b')
        
        # Show as colored binary
        visual = ""
        for i, bit in enumerate(binary):
            if i % 8 == 0 and i != 0:
                visual += " "
            
            if bit == '1':
                visual += f"\033[94m1\033[0m"  # Blue for network
            else:
                visual += f"\033[92m0\033[0m"  # Green for host
        
        return visual
    
    def print_summary(self):
        """Print comprehensive IP subnet information."""
        print("\n" + "=" * 70)
        print("🌐 IP SUBNET CALCULATOR - VISUAL BREAKDOWN")
        print("=" * 70)
        
        # Basic Information
        print("\n📋 BASIC INFORMATION")
        print("-" * 70)
        print(f"IP Address:           {self.ip}")
        print(f"CIDR Notation:        {self.network.with_prefixlen}")
        print(f"Subnet Mask:          {self.subnet_mask}")
        print(f"Network Bits:         {self.cidr}")
        print(f"Host Bits:            {32 - self.cidr}")
        
        # Binary Breakdown
        print("\n📊 BINARY BREAKDOWN")
        print("-" * 70)
        print(f"IP Address Binary:    {self.get_binary_breakdown(self.ip)}")
        print(f"Subnet Mask Binary:   {self.visualize_subnet_mask()}")
        
        # Color legend
        print(f"\n  {"\033[94m"}■\033[0m = Network portion (CIDR /{self.cidr})")
        print(f"  {"\033[92m"}■\033[0m = Host portion ({32 - self.cidr} bits)")
        
        # Octet Breakdown
        print("\n📍 OCTET BREAKDOWN")
        print("-" * 70)
        print(self.get_octet_breakdown(self.ip), end="")
        
        # Network Calculations
        print("\n🔧 NETWORK CALCULATIONS")
        print("-" * 70)
        print(f"Network Address:      {self.network.network_address}")
        print(f"Broadcast Address:    {self.network.broadcast_address}")
        print(f"First Host Address:   {self.network.network_address + 1}")
        print(f"Last Host Address:    {self.network.broadcast_address - 1}")
        print(f"Total Addresses:      {self.network.num_addresses}")
        print(f"Usable Hosts:         {max(0, self.network.num_addresses - 2)}")
        
        # Visual Network Range
        print("\n📈 HOST RANGE VISUALIZATION")
        print("-" * 70)
        self.print_host_range()
        
        # Subnet Information
        print("\n🔐 SUBNET INFORMATION")
        print("-" * 70)
        print(f"Class:                {self.get_ip_class(self.ip)}")
        print(f"Type:                 {self.get_network_type()}")
        
        print("\n" + "=" * 70 + "\n")
    
    def print_host_range(self):
        """Print visual representation of host range."""
        total_hosts = max(0, self.network.num_addresses - 2)
        
        if total_hosts == 0:
            print("  (No usable host addresses in this subnet)")
            return
        
        # Show range
        first = self.network.network_address + 1
        last = self.network.broadcast_address - 1
        
        print(f"  {self.network.network_address} (Network)")
        print(f"  ↓")
        print(f"  {first} ─┐")
        
        if total_hosts > 4:
            print(f"  {first + 1}")
            print(f"  {first + 2}")
            print(f"  ...")
            print(f"  {last - 2}")
            print(f"  {last - 1}")
        else:
            for host in range(first, last + 1):
                print(f"  {host}")
        
        print(f"  {last} ─┘")
        print(f"  ↓")
        print(f"  {self.network.broadcast_address} (Broadcast)")
    
    @staticmethod
    def get_ip_class(ip_addr) -> str:
        """Determine IP class (A, B, C, D, E)."""
        first_octet = int(str(ip_addr).split('.')[0])
        
        if first_octet < 128:
            return "Class A (1-126)"
        elif first_octet < 192:
            return "Class B (128-191)"
        elif first_octet < 224:
            return "Class C (192-223)"
        elif first_octet < 240:
            return "Class D (224-239) - Multicast"
        else:
            return "Class E (240-255) - Reserved"
    
    def get_network_type(self) -> str:
        """Identify network type (private, loopback, etc)."""
        if self.network.is_private:
            return "Private Network"
        elif self.network.is_loopback:
            return "Loopback"
        elif self.network.is_link_local:
            return "Link-Local"
        elif self.network.is_multicast:
            return "Multicast"
        elif self.network.is_reserved:
            return "Reserved"
        else:
            return "Public Network"
    
    def validate_host(self, host_ip: str) -> bool:
        """Check if a host IP is in this subnet."""
        try:
            ip = ipaddress.ip_address(host_ip)
            return ip in self.network
        except ValueError:
            return False
    
    def split_subnet(self, subnets: int) -> List:
        """Split this subnet into smaller subnets."""
        try:
            return list(self.network.subnets(new_prefix=self.cidr + subnets.bit_length()))
        except ValueError as e:
            print(f"❌ Cannot create {subnets} subnets: {e}")
            return []


def print_menu():
    """Print interactive menu."""
    print("\n" + "=" * 70)
    print("🌐 IP SUBNET CALCULATOR")
    print("=" * 70)
    print("\nOptions:")
    print("1. Analyze single IP with subnet mask")
    print("2. Validate host IP in subnet")
    print("3. View common subnet masks")
    print("4. Exit")
    print()


def show_common_masks():
    """Display common subnet masks and their CIDR equivalents."""
    print("\n" + "=" * 70)
    print("📚 COMMON SUBNET MASKS & CIDR NOTATION")
    print("=" * 70)
    
    common = [
        ("255.255.255.0", "/24", "256 addresses", "Class C standard"),
        ("255.255.255.128", "/25", "128 addresses", "Subnet Class C"),
        ("255.255.255.192", "/26", "64 addresses", "Subnet Class C"),
        ("255.255.255.224", "/27", "32 addresses", "Subnet Class C"),
        ("255.255.255.240", "/28", "16 addresses", "Subnet Class C"),
        ("255.255.0.0", "/16", "65,536 addresses", "Class B standard"),
        ("255.0.0.0", "/8", "16,777,216 addresses", "Class A standard"),
        ("10.0.0.0", "/8", "Private (Class A)", "RFC 1918"),
        ("172.16.0.0", "/12", "Private (Class B)", "RFC 1918"),
        ("192.168.0.0", "/16", "Private (Class C)", "RFC 1918"),
    ]
    
    print(f"\n{'Subnet Mask':<20} {'CIDR':<8} {'Addresses':<20} {'Type':<20}")
    print("-" * 70)
    for mask, cidr, addresses, desc in common:
        print(f"{mask:<20} {cidr:<8} {addresses:<20} {desc:<20}")
    
    print("\n" + "=" * 70 + "\n")


def main():
    """Main interactive function."""
    print("\n" + "=" * 70)
    print("🌐 IP SUBNET CALCULATOR WITH VISUAL BREAKDOWN")
    print("=" * 70)
    print("\nLearn subnetting with visual byte-level breakdowns!")
    
    while True:
        print_menu()
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == '1':
            ip_input = input("\nEnter IP with subnet mask (e.g., 192.168.1.0/24): ").strip()
            
            if not ip_input:
                print("❌ Invalid input!")
                continue
            
            calc = IPCalculator(ip_input)
            calc.print_summary()
            
            # Ask if user wants to validate hosts
            while True:
                test_ip = input("Test a host IP in this network (or press Enter to go back): ").strip()
                if not test_ip:
                    break
                
                if calc.validate_host(test_ip):
                    print(f"✅ {test_ip} is in this subnet!")
                else:
                    print(f"❌ {test_ip} is NOT in this subnet!")
        
        elif choice == '2':
            ip_input = input("\nEnter subnet (e.g., 192.168.1.0/24): ").strip()
            host_ip = input("Enter host IP to validate: ").strip()
            
            calc = IPCalculator(ip_input)
            if calc.validate_host(host_ip):
                print(f"\n✅ {host_ip} is in {ip_input}")
            else:
                print(f"\n❌ {host_ip} is NOT in {ip_input}")
        
        elif choice == '3':
            show_common_masks()
        
        elif choice == '4':
            print("\n👋 Goodbye!\n")
            break
        
        else:
            print("❌ Invalid choice!")


if __name__ == "__main__":
    main()
