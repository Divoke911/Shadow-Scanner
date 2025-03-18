import socket
import threading

def scan_port(target, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))

        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown"

            open_port_info = f"[+] Port {port} is open ({service})"
            print(open_port_info)
            results.append(open_port_info)

        s.close()
    except:
        pass

def port_scanner(target, start_port, end_port):
    print(f"\nScanning {target} for open ports...\n")

    results = []
    threads = []

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(target, port, results))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    if results:
        with open("Scan_Results.txt", "w") as file:
            file.write("\n".join(results))
        print("\n Scan completed. Results saved in 'Scan_Results.txt'.")
    else:
        print("\n No open ports found.")

target = input("Enter IP Of Target To Scan: ")
start_port = int(input("Enter start port: "))
end_port = int(input("Enter end port: "))

port_scanner(target, start_port, end_port)