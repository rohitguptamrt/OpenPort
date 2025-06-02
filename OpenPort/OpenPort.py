import psutil
import csv
import logging
import socket  # Add this at the top with other imports
from datetime import datetime
import platform

# Set up logging
logging.basicConfig(filename='open_ports.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
# Define risky ports and their details
RISKY_PORTS = {
    23: {"service": "Telnet", "risk": "Unencrypted protocol, vulnerable to eavesdropping", 
         "recommendation": "Close port or disable Telnet service"},
    3389: {"service": "RDP", "risk": "Targeted for brute-force attacks", 
           "recommendation": "Restrict to VPN or disable if unused"},
    445: {"service": "SMB", "risk": "Exploited by ransomware (e.g., EternalBlue)", 
          "recommendation": "Block unless required for file sharing"},
    21: {"service": "FTP", "risk": "Unencrypted, prone to data interception", 
         "recommendation": "Use SFTP or disable FTP"},
    1433: {"service": "SQL Server", "risk": "Targeted for database attacks", 
           "recommendation": "Restrict to internal networks"}
}

def collect_open_ports():
    """Collect all open network ports and their details."""
    try:
        # Get all network connections
        connections = psutil.net_connections(kind='inet')
        port_data = []

        # Extract details for each connection
        for conn in connections:
            try:
                data = {
                    'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                    'local_address': conn.laddr.ip if conn.laddr else 'N/A',
                    'local_port': conn.laddr.port if conn.laddr else 'N/A',
                    'remote_address': conn.raddr.ip if conn.raddr else 'N/A',
                    'remote_port': conn.raddr.port if conn.raddr else 'N/A',
                    'status': conn.status if conn.status else 'N/A',
                    'pid': conn.pid if conn.pid else 'N/A',
                    'security_status': 'Safe'
                }
                port_data.append(data)
            except Exception as e:
                logging.error(f"Error processing connection: {e}")
                continue

        logging.info(f"Collected {len(port_data)} open ports")
        return port_data
    except Exception as e:
        logging.error(f"Error collecting open ports: {e}")
        return []


def analyze_ports_security(port_data):
    """Analyze open ports for security risks."""
    for data in port_data:
        port = data['local_port']
        if port != 'N/A' and int(port) in RISKY_PORTS:
            data['security_status'] = f"Risky: {RISKY_PORTS[int(port)]['risk']}"
            data['recommendation'] = RISKY_PORTS[int(port)]['recommendation']
            data['service'] = RISKY_PORTS[int(port)]['service']
            # Generate platform-specific firewall command
            if platform.system() == "Windows":
                data['firewall_cmd'] = f'netsh advfirewall firewall add rule name="Block {port}" dir=in action=block protocol={data["protocol"]} localport={port}'
            elif platform.system() == "Linux":
                data['firewall_cmd'] = f'sudo ufw deny {port}/{data["protocol"].lower()}'
            else:
                data['firewall_cmd'] = 'Manual configuration required'
            logging.warning(f"Risky port detected: {port} ({data['service']})")
        else:
            data['recommendation'] = 'No action needed'
            data['service'] = 'Unknown'
            data['firewall_cmd'] = 'N/A'

    return port_data

def save_to_csv(port_data, filename='open_ports_security_report.csv'):
    """Save open port data with security analysis to a CSV file."""
    try:
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['protocol', 'local_address', 'local_port', 'remote_address', 
                          'remote_port', 'status', 'pid', 'service', 'security_status', 
                          'recommendation', 'firewall_cmd']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for data in port_data:
                writer.writerow(data)
        logging.info(f"Saved open ports security report to {filename}")
    except Exception as e:
        logging.error(f"Error saving to CSV: {e}")

def main():
    """Main function to collect, analyze, and save open ports with security report."""
    logging.info("Starting open ports collection and security analysis")
    port_data = collect_open_ports()
    
    if port_data:
        port_data = analyze_ports_security(port_data)
        save_to_csv(port_data)
        print("Open Ports Security Report:")
        print("=" * 50)
        for data in port_data:
            print(f"Protocol: {data['protocol']}, Local: {data['local_address']}:{data['local_port']}, "
                  f"Remote: {data['remote_address']}:{data['remote_port']}, Status: {data['status']}, "
                  f"PID: {data['pid']}, Service: {data['service']}, Security: {data['security_status']}")
            if data['security_status'].startswith('Risky'):
                print(f"Recommendation: {data['recommendation']}")
                print(f"Firewall Command: {data['firewall_cmd']}")
                print("-" * 50)
    else:
        print("No open ports found or an error occurred.")

if __name__ == "__main__":
    main()