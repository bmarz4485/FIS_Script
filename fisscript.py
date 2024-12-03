import subprocess
from datetime import datetime
import os
import re


def sanitize_name(name):
    """Sanitize names (for directories and file names) using an allowlist approach."""
    allowed_characters = re.compile(r'[^a-zA-Z0-9_\-./]')
    sanitized = allowed_characters.sub('_', name)  # Replace disallowed characters with '_'
    sanitized = sanitized.replace('//', '/').strip('/')  # Ensure no double slashes and remove trailing slashes
    return sanitized


def clean_url(url):
    """Clean the URL to strip out protocols, fragments, and query strings."""
    url = re.sub(r'^https?://', '', url)  # Remove http:// or https://
    url = url.split('#')[0]  # Remove fragments
    url = url.split('?')[0]  # Remove query strings
    return sanitize_name(url)


def get_output_directory():
    """Ask the user for the output directory and ensure it exists."""
    while True:
        output_dir = input("Enter the output directory (use '.' for the current working directory): ").strip()
        sanitized_dir = sanitize_name(output_dir)

        if sanitized_dir != output_dir:
            print(f"Warning: The directory name contained invalid characters. Sanitized to: {sanitized_dir}")
            confirm = input("Do you want to use the sanitized directory name? (y/n): ").strip().lower()
            if confirm != 'y':
                continue

        if sanitized_dir == ".":
            sanitized_dir = os.getcwd()  # Use the current working directory

        if not os.path.exists(sanitized_dir):
            print(f"Directory '{sanitized_dir}' does not exist. Creating it...")
            try:
                os.makedirs(sanitized_dir)  # Create the directory
            except OSError as e:
                print(f"Error creating directory: {e}")
                continue
        return sanitized_dir  # Return the valid directory


def parse_nmap_output(nmap_output_file):
    """Parse Nmap output to find open web application ports."""
    web_ports = set()
    try:
        with open(nmap_output_file, "r") as file:
            for line in file:
                if "open" in line and ("http" in line or "https" in line):
                    port = line.split("/")[0].strip()
                    web_ports.add(int(port))  # Add port as an integer
    except FileNotFoundError:
        print(f"Error: Nmap output file {nmap_output_file} not found.")
    return list(web_ports)  # Return as a list


def run_nmap(ip_address, output_dir):
    """Run an Nmap scan based on user-selected options."""
    print("\nConfiguring Nmap scan...")

    # Present scan type options to the user
    print("\nChoose the type of scan options (you can select multiple):")
    print("1. Stealth scan (SYN scan)")
    print("2. Verbose output")
    print("3. Full port scan (all 65535 ports)")
    print("4. Version scan")
    print("5. Top 1000 port scan (default)")
    print("6. Ping scan (determine live hosts)")
    print("7. OS detection")
    print("8. Script scan (default Nmap scripts)")
    print("9. Aggressive scan (OS + version + script + traceroute)")
    print("10. Disable DNS resolution (faster scans)")
    print("\nType the numbers corresponding to your choices. Type 'done' when finished.")

    # Collect scan options
    nmap_options = []
    option_mapping = {
        "1": "-sS",  # Stealth scan
        "2": "-v",  # Verbose
        "3": "-p-",  # Full port scan
        "4": "-sV",  # Version scan
        "5": "",  # Top 1000 port scan (default, no option needed)
        "6": "-sn",  # Ping scan
        "7": "-O",  # OS detection
        "8": "-sC",  # Script scan
        "9": "-A",  # Aggressive scan
        "10": "-n",  # Disable DNS resolution
    }

    while True:
        choice = input("Enter your choice (1-10 or 'done'): ").strip()
        if choice == "done":
            if not nmap_options:
                print("No options selected. Adding default top 1000 port scan.")
                nmap_options.append("")  # Default top 1000 port scan
            break
        elif choice in option_mapping:
            if option_mapping[choice] not in nmap_options:
                nmap_options.append(option_mapping[choice])
                print(f"Added option {choice}")
            else:
                print(f"Option {choice} already added.")
        else:
            print("Invalid choice. Please select a valid option.")

    # Combine all selected options
    nmap_options_str = " ".join(nmap_options)

    # Sanitize the IP or domain for use in file names
    sanitized_ip_address = clean_url(ip_address)

    # Get the current date and time for the file name
    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    output_file = os.path.join(output_dir, f"nmap_scan_{sanitized_ip_address}_{timestamp}.txt")

    # Build the final Nmap command
    command = f"nmap {nmap_options_str} {ip_address}"

    # Run the Nmap command and save the output to the file
    print(f"\nRunning the Nmap scan: {command}")
    try:
        with open(output_file, "w") as file:
            subprocess.run(command.split(), stdout=file, text=True)
        print(f"\nNmap scan completed. Results saved to: {output_file}")
    except FileNotFoundError as e:
        print(f"Error saving results: {e}")
    return output_file


def run_gobuster(ip_address, web_ports, output_dir):
    """Run Gobuster scans for specified web application ports."""
    for port in web_ports:
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{ip_address}:{port}"
        wordlist = input(f"Enter the path to your wordlist for port {port}: ").strip()
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        output_file = os.path.join(output_dir, f"{port}_gobuster_scan_{timestamp}.txt")

        command = f"gobuster dir -u {url} -w {wordlist}"
        print(f"\nRunning Gobuster scan on port {port}: {command}")
        try:
            with open(output_file, "w") as file:
                subprocess.run(command.split(), stdout=file, text=True)
            print(f"Gobuster scan for port {port} completed. Results saved to: {output_file}")
        except FileNotFoundError as e:
            print(f"Error saving results: {e}")


def main():
    """Main function to handle user choices."""
    print("Choose the tool to use:")
    print("1. Nmap")
    print("2. Gobuster")
    print("3. Both Nmap and Gobuster")
    choice = input("Enter your choice (1/2/3): ").strip()

    if choice in ["1", "2", "3"]:
        ip_address = input("Enter the target IP address or domain: ").strip()
        output_dir = get_output_directory()
    else:
        print("Invalid choice. Exiting.")
        return

    if choice == "1":
        # Run Nmap and parse output
        nmap_output_file = run_nmap(ip_address, output_dir)
        web_ports = parse_nmap_output(nmap_output_file)

        if web_ports:
            print("\nPotential Web Application Ports Detected:")
            print("Review the following lines to ensure these are valid web applications before proceeding.")
            try:
                # Open the Nmap output file and print lines corresponding to web application ports
                with open(nmap_output_file, "r") as file:
                    lines = file.readlines()
                    for line in lines:
                        for port in web_ports:
                            if f"{port}/" in line:  # Match the port within the output line
                                print(f"Port {port}: {line.strip()}")  # Print the entire line for the port
            except FileNotFoundError:
                print(f"Error: Could not open Nmap output file {nmap_output_file} for review.")

            # Ask the user if they want to run Gobuster on the detected web ports
            while True:
                print("\nDo you want to:")
                print(f"1. Scan all detected ports ({', '.join(map(str, web_ports))}) with Gobuster")
                print("2. Select specific ports")
                print("3. Skip Gobuster and exit")
                prompt = input("Enter your choice (1/2/3): ").strip()

                if prompt == "1":
                    # Run Gobuster on all detected web application ports
                    print(f"\nRunning Gobuster on all detected ports: {', '.join(map(str, web_ports))}")
                    run_gobuster(ip_address, web_ports, output_dir)
                    break
                elif prompt == "2":
                    # Let the user select specific ports for Gobuster
                    gobuster_ports = []
                    while True:
                        print(f"\nPorts available for selection: {', '.join(map(str, web_ports))}" if web_ports else "No ports left to select.")
                        print(f"Ports already added for Gobuster scan: {', '.join(map(str, gobuster_ports))}" if gobuster_ports else "No ports added yet.")

                        port_choice = input("Enter a port to scan (or 'done' to finish selection): ").strip()
                        if port_choice == "done":
                            break
                        elif port_choice.isdigit() and int(port_choice) in web_ports:
                            selected_port = int(port_choice)
                            gobuster_ports.append(selected_port)
                            web_ports.remove(selected_port)  # Remove the selected port from the web_ports list
                            print(f"Added port {selected_port} for Gobuster scan.")
                        else:
                            print(f"Invalid input. Please enter a valid port from the list: {', '.join(map(str, web_ports))}.")
                    
                    # Run Gobuster if any ports were selected
                    if gobuster_ports:
                        print(f"\nFinal list of ports selected for Gobuster scan: {', '.join(map(str, gobuster_ports))}")
                        run_gobuster(ip_address, gobuster_ports, output_dir)
                    else:
                        print("No ports selected. Skipping Gobuster.")
                    break
                elif prompt == "3":
                    # Skip Gobuster and exit
                    print("No further scans selected. Skipping Gobuster.")
                    break
                else:
                    print("Invalid input. Please type '1', '2', or '3'.")
        else:
            print("No potential web application ports detected. Skipping Gobuster.")





    elif choice == "2":
        print("\nConfiguring Gobuster scan...")
        web_ports = input("Enter the ports to scan (comma-separated, e.g., 80,443): ").split(",")
        run_gobuster(ip_address, web_ports, output_dir)

    elif choice == "3":
        # Run Nmap first
        nmap_output_file = run_nmap(ip_address, output_dir)
        web_ports = parse_nmap_output(nmap_output_file)

        if web_ports:
            print("\nPotential Web Application Ports Detected:")
            print("Review the following lines to ensure these are valid web applications before proceeding.")
            try:
                # Open the Nmap output file and print lines corresponding to web application ports
                with open(nmap_output_file, "r") as file:
                    lines = file.readlines()
                    for line in lines:
                        for port in web_ports:
                            if f"{port}/" in line:  # Match the port within the output line
                                print(f"Port {port}: {line.strip()}")  # Print the entire line for the port
            except FileNotFoundError:
                print(f"Error: Could not open Nmap output file {nmap_output_file} for review.")
                return

            # Interactive prompt for selecting Gobuster options
            while True:
                print(f"\nDo you want to:")
                print(f"1. Scan all detected ports ({', '.join(map(str, web_ports))}) with Gobuster")
                print("2. Select specific ports")
                print("3. Exit without running Gobuster")
                prompt = input("Enter your choice (1/2/3): ").strip()

                if prompt == "1":
                    # Run Gobuster on all detected web application ports
                    print(f"\nRunning Gobuster on all detected ports: {', '.join(map(str, web_ports))}")
                    run_gobuster(ip_address, web_ports, output_dir)
                    break
                elif prompt == "2":
                    gobuster_ports = []
                    while True:
                        print(f"\nPorts available for selection: {', '.join(map(str, web_ports))}" if web_ports else "No ports left to select.")
                        print(f"Ports already added for Gobuster scan: {', '.join(map(str, gobuster_ports))}" if gobuster_ports else "No ports added yet.")

                        port = input("Enter a port to scan (or 'done' to finish): ").strip()
                        if port == "done":
                            break
                        if port.isdigit() and int(port) in web_ports:
                            selected_port = int(port)
                            gobuster_ports.append(selected_port)
                            web_ports.remove(selected_port)  # Remove from available ports
                            print(f"Added port {selected_port} for Gobuster scan.")
                        else:
                            print(f"Invalid input. Please enter a valid port from the list: {', '.join(map(str, web_ports))}.")
                    if gobuster_ports:
                        print(f"\nFinal list of ports selected for Gobuster scan: {', '.join(map(str, gobuster_ports))}")
                        run_gobuster(ip_address, gobuster_ports, output_dir)
                    else:
                        print("No ports selected. Skipping Gobuster scan.")
                    break
                elif prompt == "3":
                    print("No further scans selected. Exiting script.")
                    break
                else:
                    print("Invalid input. Please type '1', '2', or '3'.")







if __name__ == "__main__":
    main()
