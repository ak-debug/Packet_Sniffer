
# Packet Sniffer

This is a packet sniffing script written in Python using the Scapy library. It allows you to capture and analyze network packets on a specified interface. The script provides options to filter packets based on a filter expression and keyword, and it saves the captured packets to a log file.

## Features

- Capture network packets on a specified interface.
- Filter packets based on a filter expression in BPF syntax.
- Filter packets based on a keyword in the payload.
- Limit the number of packets captured.
- Save captured packets and relevant information to a log file.

## Requirements

- Python 3.x
- Scapy library (`pip install scapy`)

**Note:**

- When running the script, you might need to use `sudo` or run the script as an administrator, depending on your operating system and network interface permissions. This is required to have the necessary permissions for capturing network packets.

## Usage

```
python sniff.py [-h] [-i INTERFACE] [-e EXPRESSION] [-f FILTER] [-l LOG] [-c COUNT]
```

### Options

- `-h, --help`: Show the help message and usage information.
- `-i INTERFACE, --interface INTERFACE`: Specify the interface to sniff on. Default: eth0.
- `-e EXPRESSION, --expression EXPRESSION`: Specify the filter expression in BPF syntax (optional).
- `-f FILTER, --filter FILTER`: Filter keyword to limit the sniffing (optional).
- `-l LOG, --log LOG`: Specify the log file to save the captured packets. Default: sniff_log.txt.
- `-c COUNT, --count COUNT`: Specify the maximum number of packets to capture (optional).

## Examples

1. Capture packets on the default interface (eth0) and save to the default log file (sniff_log.txt):
```
python sniff.py
```

2. Capture packets on a specific interface (e.g., wlan0) and save to a specific log file (capture.log):
```
python sniff.py -i wlan0 -l capture.log
```

3. Capture HTTP packets with a filter expression and filter for a specific keyword:
```
python sniff.py -e "tcp port 80" -f password
```

## Notes

- Make sure to have the necessary permissions and comply with legal and ethical considerations when capturing and analyzing network traffic.
- Depending on your operating system and network interface permissions, you might need to run the script with `sudo` or as an administrator to have the necessary permissions for capturing network packets.

