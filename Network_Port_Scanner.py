import nmap

scanner = nmap.PortScanner()

print("Welcome to Network Scanner")

try:
    trgt = input("Enter the IP or Domain To Scan: ")
    
    print("\nSelect Scan Type:")
    print("1) SYN ACK Scan")
    print("2) UDP Scan")
    print("3) Comprehensive Scan")
    
    option = input("Enter Option (1/2/3): ")

    if option == "1":
        print("\nPerforming SYN ACK Scan...")
        arguments = "-v -sS"
    elif option == "2":
        print("\nPerforming UDP Scan...")
        arguments = "-v -sU"
    elif option == "3":
        print("\nPerforming Comprehensive Scan...")
        arguments = "-v -sS -sV -sC -A -O"
    else:
        print("Invalid Option. Exiting.")
        exit()

    print(f"\nScanning {trgt} with arguments: {arguments}\n")
    scanner.scan(trgt, "1-1024", arguments=arguments)

    with open("scan_report.txt", "w") as report:
        for host in scanner.all_hosts():
            result = f"\nHost: {host} ({scanner[host].hostname()})\n"
            result += f"State: {scanner[host].state()}\n"
            for proto in scanner[host].all_protocols():
                result += f"\nProtocol: {proto}\n"
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    state = scanner[host][proto][port]['state']
                    result += f"Port: {port}\tState: {state}\n"
            print(result)
            report.write(result)

    print("\nScan complete. Results saved to scan_report.txt")
except KeyboardInterrupt:
    print("\nScan canceled by user.")

except Exception as e:
    print(f"An error occurred: {e}")
