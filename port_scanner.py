import nmap
import argparse
import sys

def scan_target(target, report_file_name):
    # Initialize the Nmap scanner
    scanner = nmap.PortScanner()

    try:
        # Run the scan on the target
        print(f"Scanning target: {target}...")
        scanner.scan(hosts=target, arguments='-sS')  # TCP SYN scan
        
        # Open the report file in write mode
        with open(report_file_name, 'w') as report_file:
            for host in scanner.all_hosts():
                report_file.write(f"Host : {host} ({scanner[host].hostname()})\n")
                report_file.write(f"State : {scanner[host].state()}\n")

                for proto in scanner[host].all_protocols():
                    report_file.write(f"Protocol : {proto}\n")
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        report_file.write(f"Port : {port}\tState : {scanner[host][proto][port]['state']}\n")
        
        print(f"Scan completed. Results saved to {report_file_name}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == '__main__':
    # Argument parsing with argparse
    parser = argparse.ArgumentParser(description="A simple Nmap-based port scanning script.")
    parser.add_argument('target', help='Target IP address or domain to scan (e.g., 192.168.1.1 or example.com)')
    parser.add_argument('report_file', help='Output file name to save the scan results (e.g., report.txt)')
    
    args = parser.parse_args()

    # Perform the scan
    scan_target(args.target, args.report_file)