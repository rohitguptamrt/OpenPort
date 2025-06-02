import psutil
import csv
import logging
import socket  # Add this at the top with other imports
from datetime import datetime

# Set up logging
logging.basicConfig(filename='open_ports.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
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
                    'pid': conn.pid if conn.pid else 'N/A'
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

def save_to_csv(port_data, filename='open_ports.csv'):
    """Save open port data to a CSV file."""
    try:
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['protocol', 'local_address', 'local_port', 'remote_address', 'remote_port', 'status', 'pid']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for data in port_data:
                writer.writerow(data)
        logging.info(f"Saved open ports to {filename}")
    except Exception as e:
        logging.error(f"Error saving to CSV: {e}")

def main():
    """Main function to collect and save open ports."""
    logging.info("Starting open ports collection")
    port_data = collect_open_ports()
    
    if port_data:
        save_to_csv(port_data)
        for data in port_data:
            print(f"Protocol: {data['protocol']}, Local: {data['local_address']}:{data['local_port']}, "
                  f"Remote: {data['remote_address']}:{data['remote_port']}, Status: {data['status']}, PID: {data['pid']}")
    else:
        print("No open ports found or an error occurred.")

if __name__ == "__main__":
    main()