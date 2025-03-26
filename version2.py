import customtkinter as ctk
import socket
import threading
from scapy.all import ARP, Ether, srp

# Function to find connected devices on the network
def find_devices():
    network_ip = entry_ip.get() + "/24"  # Assuming a subnet mask of 255.255.255.0
    text_output.insert(ctk.END, f"Scanning network {network_ip} for connected devices...\n")
    
    arp_request = ARP(pdst=network_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    result = srp(packet, timeout=2, verbose=False)[0]
    
    devices = [received.psrc for sent, received in result]

    if devices:
        text_output.insert(ctk.END, f"Devices found: {len(devices)}\n")
        device_selector.configure(values=devices)
        device_selector.set(devices[0])  # Select the first device by default
    else:
        text_output.insert(ctk.END, "No devices found on the network.\n")

# Function to scan a single port
def scan_port(target, port, results, text_widget):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))

        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown"

            open_port_info = f"[+] {target}:{port} is open ({service})"
            results.append(open_port_info)
            text_widget.insert(ctk.END, open_port_info + "\n")
        
        s.close()
    except:
        pass

# Function to start scanning for open ports
def port_scanner():
    thread = threading.Thread(target=run_scan)
    thread.start()

def run_scan():
    text_output.delete("1.0", ctk.END)

    target_device = device_selector.get()  # Get selected device from dropdown
    start_port = int(entry_start_port.get())
    end_port = int(entry_end_port.get())

    text_output.insert(ctk.END, f"\nScanning {target_device} for open ports...\n")

    results = []
    threads = []

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(target_device, port, results, text_output))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    if results:
        text_output.insert(ctk.END, "\nScan completed. Saving results...\n")
        with open("Scan_Results.txt", "w") as file:
            file.write("\n".join(results))
        text_output.insert(ctk.END, "Results saved in 'Scan_Results.txt'.\n")
    else:
        text_output.insert(ctk.END, "\nNo open ports found.\n")

# UI Setup
ctk.set_appearance_mode("dark") 
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Network Port Scanner")
app.geometry("600x550")

label_ip = ctk.CTkLabel(app, text="Enter Network IP (e.g., 192.168.1.1):")
label_ip.pack(pady=5)
entry_ip = ctk.CTkEntry(app)
entry_ip.pack(pady=5)

button_find_devices = ctk.CTkButton(app, text="Find Connected Devices", command=find_devices)
button_find_devices.pack(pady=10)

label_device = ctk.CTkLabel(app, text="Select Target Device:")
label_device.pack(pady=5)
device_selector = ctk.CTkComboBox(app, values=[])  # Dropdown for device selection
device_selector.pack(pady=5)

label_start_port = ctk.CTkLabel(app, text="Start Port:")
label_start_port.pack(pady=5)
entry_start_port = ctk.CTkEntry(app)
entry_start_port.pack(pady=5)

label_end_port = ctk.CTkLabel(app, text="End Port:")
label_end_port.pack(pady=5)
entry_end_port = ctk.CTkEntry(app)
entry_end_port.pack(pady=5)

button_scan = ctk.CTkButton(app, text="Start Scan", command=port_scanner)
button_scan.pack(pady=10)

text_output = ctk.CTkTextbox(app, height=200, wrap="word")
text_output.pack(pady=10, padx=10, fill="both", expand=True)

app.mainloop()
