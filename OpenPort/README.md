# OpenPort - Open Ports Security Analyzer

OpenPort is a Python utility that scans your system for open network ports, analyzes them for common security risks, and generates a detailed CSV report. It highlights risky ports, provides recommendations, and suggests platform-specific firewall commands to help secure your system.

## Features

- Lists all open TCP and UDP ports with details (addresses, ports, status, PID).
- Identifies commonly exploited or risky ports (e.g., Telnet, RDP, SMB, FTP, SQL Server).
- Provides security risk analysis and actionable recommendations.
- Suggests firewall commands for Windows and Linux to block risky ports.
- Outputs results to a CSV file and logs actions to a log file.

## Requirements

- Python 3.6+
- `psutil` library

## Installation

1. Clone or download this repository.
2. Install the required Python package:

## Usage

Run the script from the command line:


- The script will print a summary to the console.
- A detailed report will be saved as `open_ports_security_report.csv`.
- Logs are written to `open_ports.log`.

## Output

- **CSV Report:** Contains protocol, addresses, ports, status, PID, service, security status, recommendations, and firewall commands.
- **Console:** Summarizes each open port and highlights risky ones with recommendations.

## Customization

- To add or modify risky ports, edit the `RISKY_PORTS` dictionary in `OpenPort.py`.

## Disclaimer

This tool is for informational and educational purposes. Always review and test firewall commands before applying them to production systems.

## License

MIT License