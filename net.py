import gradio as gr
from network_diagnostic_skills import (
    NetworkDiagnosticSkill,
    DNSLookupSkill,
    PortScannerSkill,
    NetworkInterfaceSkill,
    BandwidthTestSkill,
    PacketSnifferSkill,
    ARPScanSkill,
    TCPConnectionTestSkill,
    LatencyMonitorSkill,
    RouteTableSkill,
    # Removed traceroute direct import as it's part of NetworkDiagnosticSkill
)

# Initialize the skills
network_diagnostic = NetworkDiagnosticSkill()
dns_lookup = DNSLookupSkill()
port_scanner = PortScannerSkill()
interface_info = NetworkInterfaceSkill()
bandwidth_test = BandwidthTestSkill()
packet_sniffer = PacketSnifferSkill()
arp_scan = ARPScanSkill()
tcp_test = TCPConnectionTestSkill()
latency_monitor = LatencyMonitorSkill()
route_table = RouteTableSkill()


# Define the callback functions for each skill
def ping_skill(target_ip, packet_size, count, timeout):
    return network_diagnostic.ping(target_ip, int(packet_size), int(count), int(timeout))


def traceroute_skill(target_ip, max_hops, packet_size):
    return network_diagnostic.traceroute(target_ip, int(max_hops), int(packet_size))


def dns_lookup_skill(domain, record_type, dns_server):
    return dns_lookup.lookup(domain, record_type, dns_server)


def port_scan_skill(target_ip, start_port, end_port):
    return port_scanner.scan(target_ip, int(start_port), int(end_port))


def interface_info_skill():
    info = interface_info.get_info()
    if isinstance(info, dict):
        # Pretty print the dictionary
        output_str = ""
        for iface, details_list in info.items():
            output_str += f"Interface: {iface}\n"
            for details in details_list:
                output_str += f"  Family: {details.get('family', 'N/A')}\n"
                output_str += f"  Address: {details.get('address', 'N/A')}\n"
                output_str += f"  Netmask: {details.get('netmask', 'N/A')}\n"
                output_str += f"  Broadcast: {details.get('broadcast', 'N/A')}\n"
            output_str += "\n"
        return output_str.strip()
    return str(info) # Fallback for error messages


def bandwidth_test_skill(download_url, upload_url):
    return bandwidth_test.test(download_url, upload_url)


def packet_sniffer_skill(filter_expr, count):
    # PacketSnifferSkill.sniff already returns a string or error string
    return packet_sniffer.sniff(filter_expr, int(count))


def arp_scan_skill(ip_range):
    clients = arp_scan.scan(ip_range)
    if isinstance(clients, list):
        if not clients:
            return "No devices found."
        output_str = "ARP Scan Results:\n"
        for client in clients:
            output_str += f"  IP: {client.get('ip', 'N/A')}, MAC: {client.get('mac', 'N/A')}\n"
        return output_str.strip()
    return str(clients) # Fallback for error messages or "No devices found..." string


def tcp_test_skill(host, port, timeout):
    return tcp_test.test(host, int(port), int(timeout))


def latency_monitor_skill(target_ip, interval, duration):
    results = latency_monitor.monitor(target_ip, int(interval), int(duration))
    return "\n".join(results)


def route_table_skill():
    routes = route_table.get_routes()
    output = [] # Corrected initialization
    if routes and isinstance(routes[0], dict) and 'error' in routes[0]: # Check for error message
        return routes[0]['error']
    if not routes or (isinstance(routes[0], dict) and routes[0].get('status')): # Check for "No routes..." status
        return routes[0].get('status', "No routes found or failed to parse.")

    for route in routes:
        output.append(f"Destination: {route.get('destination', 'N/A')}")
        output.append(f"  Netmask:   {route.get('netmask', 'N/A')}")
        output.append(f"  Gateway:   {route.get('gateway', 'N/A')}")
        output.append(f"  Interface: {route.get('interface', 'N/A')}")
        output.append("-" * 20) # Separator
    return "\n".join(output)


# Define the Gradio interface
with gr.Blocks() as demo:
    gr.Markdown("# Network Diagnostic Suite")

    with gr.Tab("Ping"):
        with gr.Row():
            ping_target_ip = gr.Textbox(label="Target IP", placeholder="e.g., 8.8.8.8 or google.com")
            ping_packet_size = gr.Number(label="Packet Size", value=56)
            ping_count = gr.Number(label="Count", value=4, precision=0)
            ping_timeout = gr.Number(label="Timeout (seconds)", value=1)
        ping_output = gr.Textbox(label="Ping Output", lines=10, interactive=False)
        ping_button = gr.Button("Ping")
        ping_button.click(
            ping_skill, inputs=[ping_target_ip, ping_packet_size, ping_count, ping_timeout], outputs=ping_output
        )

    with gr.Tab("Traceroute"):
        with gr.Row():
            traceroute_target_ip = gr.Textbox(label="Target IP", placeholder="e.g., 8.8.8.8 or google.com")
            traceroute_max_hops = gr.Number(label="Max Hops", value=30, precision=0)
            traceroute_packet_size = gr.Number(label="Packet Size", value=40) # scapy default is 60 for ICMP
        traceroute_output = gr.Textbox(label="Traceroute Output", lines=10, interactive=False)
        traceroute_button = gr.Button("Traceroute")
        traceroute_button.click(
            traceroute_skill,
            inputs=[traceroute_target_ip, traceroute_max_hops, traceroute_packet_size],
            outputs=traceroute_output,
        )

    with gr.Tab("DNS Lookup"):
        with gr.Row():
            dns_domain = gr.Textbox(label="Domain", placeholder="e.g., google.com")
            dns_record_type = gr.Dropdown(
                label="Record Type",
                choices=["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV"],
                value="A",
            )
            dns_server = gr.Textbox(label="DNS Server", value="8.8.8.8", placeholder="e.g., 8.8.8.8")
        dns_output = gr.Textbox(label="DNS Output", lines=10, interactive=False)
        dns_button = gr.Button("Lookup")
        dns_button.click(
            dns_lookup_skill,
            inputs=[dns_domain, dns_record_type, dns_server],
            outputs=dns_output,
        )

    with gr.Tab("Port Scanner"):
        with gr.Row():
            ps_target_ip = gr.Textbox(label="Target IP", placeholder="e.g., scanme.nmap.org or an IP address")
            ps_start_port = gr.Number(label="Start Port", value=1, precision=0)
            ps_end_port = gr.Number(label="End Port", value=1024, precision=0)
        port_scan_output = gr.Textbox(label="Port Scan Output", lines=10, interactive=False)
        port_scan_button = gr.Button("Scan Ports")
        port_scan_button.click(
            port_scan_skill,
            inputs=[ps_target_ip, ps_start_port, ps_end_port],
            outputs=port_scan_output,
        )

    with gr.Tab("Interface Info"):
        interface_output = gr.Textbox(label="Interface Info", lines=10, interactive=False)
        interface_button = gr.Button("Get Network Interface Info")
        interface_button.click(interface_info_skill, inputs=[], outputs=interface_output) # Corrected inputs

    with gr.Tab("Bandwidth Test"):
        with gr.Row():
            bw_download_url = gr.Textbox(
                label="Download URL",
                value="http://speedtest.ftp.otenet.gr/files/test100Mb.db",
            )
            bw_upload_url = gr.Textbox(label="Upload URL", value="http://httpbin.org/post") # httpbin.org can be slow or rate limit
        bandwidth_output = gr.Textbox(label="Bandwidth Test Output", lines=10, interactive=False)
        bandwidth_button = gr.Button("Test Bandwidth")
        bandwidth_button.click(
            bandwidth_test_skill,
            inputs=[bw_download_url, bw_upload_url],
            outputs=bandwidth_output,
        )

    with gr.Tab("Packet Sniffer"):
        gr.Markdown("⚠️ **Warning:** Packet sniffing may require administrative/root privileges to run correctly.")
        with gr.Row():
            sniff_filter = gr.Textbox(label="BPF Filter (optional)", value="", placeholder="e.g., 'tcp port 80'")
            sniff_count = gr.Number(label="Packet Count", value=10, precision=0)
        packet_sniffer_output = gr.Textbox(label="Captured Packets Summary", lines=10, interactive=False)
        packet_sniffer_button = gr.Button("Start Sniffing")
        packet_sniffer_button.click(
            packet_sniffer_skill, inputs=[sniff_filter, sniff_count], outputs=packet_sniffer_output
        )

    with gr.Tab("ARP Scan"):
        gr.Markdown("⚠️ **Note:** ARP Scan is typically effective only on the local network segment.")
        with gr.Row():
            arp_ip_range = gr.Textbox(label="IP Range (CIDR)", value="192.168.1.0/24", placeholder="e.g., 192.168.1.0/24")
        arp_scan_output = gr.Textbox(label="ARP Scan Output", lines=10, interactive=False)
        arp_scan_button = gr.Button("Scan Local Network (ARP)")
        arp_scan_button.click(
            arp_scan_skill, inputs=[arp_ip_range], outputs=arp_scan_output
        )

    with gr.Tab("TCP Connection Test"):
        with gr.Row():
            tcp_host = gr.Textbox(label="Target Host", placeholder="e.g., google.com or an IP address")
            tcp_port = gr.Number(label="Target Port", value=80, precision=0)
            tcp_timeout = gr.Number(label="Timeout (seconds)", value=5)
        tcp_test_output = gr.Textbox(label="TCP Test Output", lines=10, interactive=False)
        tcp_test_button = gr.Button("Test TCP Connection")
        tcp_test_button.click(
            tcp_test_skill, inputs=[tcp_host, tcp_port, tcp_timeout], outputs=tcp_test_output
        )

    with gr.Tab("Latency Monitor"):
        gr.Markdown("⚠️ **Note:** This will perform repeated pings. Ensure you have permission and be mindful of network load.")
        with gr.Row():
            lat_target_ip = gr.Textbox(label="Target IP", placeholder="e.g., 8.8.8.8")
            lat_interval = gr.Number(label="Interval (seconds)", value=60, precision=0)
            lat_duration = gr.Number(label="Duration (seconds)", value=300, precision=0) # Default to 5 mins
        latency_output = gr.Textbox(label="Latency Monitor Output", lines=10, interactive=False)
        latency_button = gr.Button("Start Latency Monitoring")
        latency_button.click(
            latency_monitor_skill,
            inputs=[lat_target_ip, lat_interval, lat_duration],
            outputs=latency_output,
        )

    with gr.Tab("Route Table"):
        route_table_output = gr.Textbox(label="Route Table Output", lines=10, interactive=False)
        route_table_button = gr.Button("Get System Route Table")
        route_table_button.click(route_table_skill, inputs=[], outputs=route_table_output) # Corrected inputs

# Launch the Gradio app
if __name__ == "__main__":
    demo.launch()