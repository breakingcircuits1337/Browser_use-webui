import os
import platform
import socket
import subprocess
import time
from dns import resolver

import psutil
import requests
from scapy.all import (
    ARP,
    Ether,
    ICMP,
    IP,
    IPerror,
    TCP,
    UDP,
    sniff,
    sr1,
    srp,
    traceroute,
)

class NetworkDiagnosticSkill:
    def __init__(self):
        self.os = platform.system()

    def ping(self, target_ip: str, packet_size: int = 56, count: int = 1, timeout: int = 1) -> str:
        """
        Perform a ping operation on the target IP address.

        Args:
            target_ip (str): The IP address to ping.
            packet_size (int): Size of the ping packet (default: 56 bytes).
            count (int): Number of ping packets to send (default: 1).
            timeout (int): Timeout in seconds for each packet (default: 1).

        Returns:
            str: Plain text output of the ping results.
        """
        if self.os == "Windows":
            ping_cmd = f"ping -n {count} -l {packet_size} -w {timeout*1000} {target_ip}"
        else:
            ping_cmd = f"ping -c {count} -s {packet_size} -W {timeout} {target_ip}"

        try:
            result = subprocess.run(ping_cmd, shell=True, check=True, text=True, capture_output=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr}"

    def traceroute(self, target_ip: str, max_hops: int = 30, packet_size: int = 40) -> str:
        """
        Perform a traceroute operation to the target IP address.

        Args:
            target_ip (str): The IP address to trace the route to.
            max_hops (int): Maximum number of hops to attempt (default: 30).
            packet_size (int): Size of the probe packets (default: 40 bytes).

        Returns:
            str: Plain text output of the traceroute results.
        """
        # Note: scapy's traceroute might require root/admin privileges
        try:
            ans, unans = traceroute(target_ip, maxttl=max_hops, psize=packet_size, verbose=0)
            output = "Traceroute Results:\n"
            # Process ans for a more standard output if needed, here's a simple way
            hops = {}
            for snd, rcv in ans:
                if snd.ttl not in hops:
                    hops[snd.ttl] = rcv.src
            for ttl in sorted(hops.keys()):
                 output += f"Hop {ttl}: {hops[ttl]}\n"
            if not hops and unans: # If no successful hops, mention it
                output += "No successful hops. Check target or permissions.\n"
            return output
        except Exception as e:
            return f"Traceroute failed: {e}. (Scapy traceroute might require root/admin privileges)"

    def help(self) -> str:
        """
        Return help text for the network diagnostic skill.
        """
        return (
            "Network Diagnostic Skill\n"
            "-----------------------\n"
            "1. ping(target_ip, packet_size=56, count=1, timeout=1)\n"
            "   Perform a ping operation on the target IP address.\n"
            "2. traceroute(target_ip, max_hops=30, packet_size=40)\n"
            "   Perform a traceroute operation to the target IP address.\n"
        )

    def describe(self) -> str:
        """
        Return a description of the skill.
        """
        return (
            "This skill provides network diagnostic capabilities including ping and traceroute.\n"
            "It supports cross-platform operations and allows customization of packet size,\n"
            "number of packets, and timeout values."
        )


class DNSLookupSkill:
    def lookup(self, domain, record_type='A', dns_server='8.8.8.8'):
        try:
            res = resolver.Resolver()
            res.nameservers = [dns_server]
            answer = res.resolve(domain, record_type) # Changed from query to resolve for consistency
            return f"DNS {record_type} records for {domain}:\n" + '\n'.join([str(r) for r in answer])
        except Exception as e:
            return f"DNS lookup failed: {e}"


class PortScannerSkill:
    def scan(self, target_ip, start_port=1, end_port=1024):
        open_ports = []
        try:
            for port in range(start_port, end_port + 1):
                # Constructing IP/TCP packet for port scanning
                # SYN packet is sent (flags='S')
                packet = IP(dst=target_ip)/TCP(dport=port, flags='S')
                response = sr1(packet, timeout=1, verbose=0) # sr1 sends and receives one packet
                if response and response.haslayer(TCP):
                    # Check for SYN-ACK response (flags=0x12 or 'SA')
                    if response.getlayer(TCP).flags == 0x12:
                        open_ports.append(port)
                        # Send RST to close the connection
                        rst_packet = IP(dst=target_ip)/TCP(dport=port, sport=response.getlayer(TCP).dport, seq=response.getlayer(TCP).ack, ack=response.getlayer(TCP).seq + 1, flags='R')
                        sr1(rst_packet, timeout=1, verbose=0)
                    # Check for RST-ACK response (flags=0x14 or 'RA'), also indicates port is closed but reachable
                    # elif response.getlayer(TCP).flags == 0x14:
                    #     pass # Port is closed
            if open_ports:
                return f"Open ports on {target_ip}: {open_ports}"
            else:
                return f"No open ports found on {target_ip} in range {start_port}-{end_port}."
        except Exception as e:
            return f"Port scan failed: {e}"


class NetworkInterfaceSkill:
    def get_info(self):
        try:
            info = {}
            for interface, snics in psutil.net_if_addrs().items():
                info[interface] = []
                for snic in snics:
                    info[interface].append({
                        'family': str(snic.family),
                        'address': snic.address,
                        'netmask': snic.netmask,
                        'broadcast': snic.broadcast
                    })
            return info
        except Exception as e:
            return f"Failed to get interface info: {e}"


class BandwidthTestSkill:
    def test(self, download_url='http://speedtest.ftp.otenet.gr/files/test100Mb.db', upload_url='http://httpbin.org/post'):
        try:
            # Download test
            start_time = time.time()
            response = requests.get(download_url, stream=True)
            size = 0
            for chunk in response.iter_content(1024):
                size += len(chunk)
            download_time = time.time() - start_time
            download_speed_mbps = (size * 8 / (1024 * 1024)) / download_time if download_time > 0 else 0 # in Mbps

            # Upload test - creating a 1MB dummy payload
            dummy_payload_size = 1 * 1024 * 1024  # 1MB
            dummy_payload = {'file': ('dummy.bin', b'0' * dummy_payload_size)}
            start_time = time.time()
            requests.post(upload_url, files=dummy_payload)
            upload_time = time.time() - start_time
            upload_speed_mbps = (dummy_payload_size * 8 / (1024 * 1024)) / upload_time if upload_time > 0 else 0 # in Mbps

            return f"Download Speed: {download_speed_mbps:.2f} Mbps\nUpload Speed: {upload_speed_mbps:.2f} Mbps"
        except Exception as e:
            return f"Bandwidth test failed: {e}"


class PacketSnifferSkill:
    def sniff(self, filter_expr='', count=10, timeout=None): # Added timeout
        try:
            # Ensure user knows this might need privileges
            print("Attempting to sniff packets. This may require administrative/root privileges.")
            packets = sniff(filter=filter_expr, count=count, timeout=timeout)
            if packets:
                return "\n".join([packet.summary() for packet in packets])
            else:
                return "No packets captured."
        except PermissionError:
            return "Packet sniffing failed: Permission denied. Please run as administrator/root."
        except Exception as e:
            return f"Packet sniffing failed: {e}"


class ARPScanSkill:
    def scan(self, ip_range='192.168.1.0/24'):
        clients = []
        try:
            arp_request = ARP(pdst=ip_range)
            broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
            arp_request_broadcast = broadcast/arp_request
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

            for sent, received in answered_list:
                clients.append({'ip': received.psrc, 'mac': received.hwsrc})
            if clients:
                return clients
            else:
                return f"No devices found in range {ip_range}."
        except Exception as e:
            return f"ARP scan failed: {e}"


class TCPConnectionTestSkill:
    def test(self, host: str, port: int, timeout: int = 5) -> str:
        """
        Test TCP connection to a host and port.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                return f"Successfully connected to {host} on port {port}."
            else:
                return f"Failed to connect to {host} on port {port}. Error: {os.strerror(result)}"
        except socket.gaierror:
            return f"Failed to resolve hostname {host}."
        except Exception as e:
            return f"TCP connection test failed: {e}"
        finally:
            if 'sock' in locals():
                sock.close()

class LatencyMonitorSkill:
    def monitor(self, target_ip: str, interval: int = 60, duration: int = 3600) -> list:
        """
        Monitors latency to a target IP over a duration.
        This is a placeholder and would typically involve repeated pings.
        """
        # This is a simplified placeholder. A real implementation would
        # involve a loop, sleeping, and pinging, then collecting results.
        results = []
        end_time = time.time() + duration
        count = 0
        nd_skill = NetworkDiagnosticSkill()
        print(f"Starting latency monitoring for {target_ip} for {duration}s with {interval}s interval.")
        while time.time() < end_time:
            count += 1
            ping_result = nd_skill.ping(target_ip, count=1, timeout=max(1, interval -1)) # Ensure timeout is less than interval
            results.append(f"Ping {count} at {time.strftime('%Y-%m-%d %H:%M:%S')}: {ping_result.strip()}")
            if time.time() + interval < end_time:
                 time.sleep(interval)
            else:
                break # Avoid sleeping past duration
        return results if results else ["No latency data collected."]


class RouteTableSkill:
    def get_routes(self) -> list:
        """
        Retrieves the system's route table.
        This is a placeholder. A real implementation would parse OS-specific commands.
        """
        routes = []
        try:
            if platform.system() == "Windows":
                process = subprocess.Popen(['route', 'print', '-4'], stdout=subprocess.PIPE, text=True) # -4 for IPv4
            else: # Linux/macOS
                process = subprocess.Popen(['netstat', '-rn'], stdout=subprocess.PIPE, text=True) # -r for routing table, -n for numerical
            
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                # Basic parsing, this will need to be much more robust for actual use
                lines = stdout.strip().split('\n')
                # Example placeholder parsing (highly dependent on OS and output format)
                if platform.system() == "Windows":
                    # Find the start of the IPv4 Route Table
                    try:
                        start_index = lines.index("IPv4 Route Table") +3 # Skip headers
                        active_routes_section = True
                        for line in lines[start_index:]:
                            if "Persistent Routes:" in line or "IPv6 Route Table" in line :
                                active_routes_section = False
                            if not active_routes_section or not line.strip() or "Interface List" in line:
                                continue
                            parts = line.split()
                            if len(parts) >= 4 and parts[0] != "Network": # Basic check
                                routes.append({
                                    'destination': parts[0],
                                    'netmask': parts[1],
                                    'gateway': parts[2],
                                    'interface': parts[3]
                                })
                    except ValueError:
                        routes.append({'error': 'Could not parse IPv4 route table section'})

                else: # Linux/macOS
                    for line in lines:
                        parts = line.split()
                        if len(parts) > 3 and (parts[0] != 'Destination' and parts[0] != 'Kernel'): # Basic check
                            if parts[0] == "default":
                                dest = "0.0.0.0"
                                gateway = parts[1]
                                netmask = "0.0.0.0" # Often not shown directly for default
                                iface = parts[-1] # Interface is usually the last column
                            elif len(parts) >= 8 and platform.system() == "Linux": # Linux 'netstat -rn' example
                                dest = parts[0]
                                gateway = parts[1]
                                netmask = parts[2]
                                iface = parts[7]
                            elif len(parts) >= 6 and platform.system() == "Darwin": # macOS 'netstat -rn' example
                                dest = parts[0]
                                gateway = parts[1]
                                # Netmask not directly in this macOS output, usually found via ifconfig or ipconfig
                                netmask = "N/A"
                                iface = parts[3] if len(parts) <= 4 else parts[5] # Interface column can shift
                            else:
                                continue
                            routes.append({
                                'destination': dest,
                                'gateway': gateway,
                                'netmask': netmask,
                                'interface': iface
                            })
            else:
                routes.append({'error': f'Command failed: {stderr if stderr else "Unknown error"}'})
        except FileNotFoundError:
             routes.append({'error': 'netstat or route command not found.'})
        except Exception as e:
            routes.append({'error': f'Failed to get routes: {str(e)}'})
        
        if not routes:
            return [{'destination': 'N/A', 'gateway': 'N/A', 'netmask': 'N/A', 'interface': 'N/A', 'status': 'No routes found or failed to parse'}]
        return routes