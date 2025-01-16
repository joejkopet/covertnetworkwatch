import tkinter as tk
from tkinter import scrolledtext
import ttkbootstrap as ttk
import subprocess
import psutil
import socket
import threading
import time
import os

def main_menu():
    global root  # Make root a global variable
    root = ttk.Window(themename="superhero", title="Covert Network Watch")

    # Get the screen width and height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Define the size of the window as a percentage of the screen size
    window_width = int(screen_width * 0.7)  # 70% of the screen width
    window_height = int(screen_height * 0.7)  # 70% of the screen height

    # Set the geometry of the window
    root.geometry(f"{window_width}x{window_height}")

    root.resizable(width=False, height=False)

    versionnumber = ttk.Label(root, text='v1.0')
    versionnumber.place(relx=0.95, rely=0.95, anchor='se')

    header_label = ttk.Label(root, text="Covert Network Watch", font=("Helvetica", 20, "bold"), bootstyle="light")
    header_label.place(relx=0.5, rely=0.05, anchor="center")

    interface_label = ttk.Label(root, text="Select Interface:", bootstyle="light")
    interface_label.place(relx=0.2, rely=0.15, anchor="w")

    interface_var = tk.StringVar()
    interface_dropdown = ttk.Combobox(root, textvariable=interface_var, state="readonly")
    interface_dropdown.place(relx=0.35, rely=0.15, anchor="w")
    interface_dropdown.bind("<<ComboboxSelected>>", lambda event: display_interface_info(event, interface_var, mac_label, ipv4_label))

    mac_label = ttk.Label(root, text="MAC Address: ", bootstyle="light")
    mac_label.place(relx=0.2, rely=0.2, anchor="w")

    ipv4_label = ttk.Label(root, text="IPv4 Address: ", bootstyle="light")
    ipv4_label.place(relx=0.2, rely=0.25, anchor="w")

    fetch_all_button = ttk.Button(root, text="Start Recon", command=lambda: start_recon(interface_var), bootstyle="info-outline")
    fetch_all_button.place(relx=0.5, rely=0.3, anchor="center")

    # Dynamically positioned text boxes with scrollbars placed side by side
    create_textbox_with_scrollbar(root, "native_vlan_output", 0.05, 0.35)
    create_textbox_with_scrollbar(root, "network_device_names_output", 0.27, 0.35) 
    create_textbox_with_scrollbar(root, "network_device_models_output", 0.49, 0.35)  
    create_textbox_with_scrollbar(root, "network_device_ios_versions_output", 0.71, 0.35)  
    create_textbox_with_scrollbar(root, "network_device_management_ips_output", 0.05, 0.52)
    create_textbox_with_scrollbar(root, "network_device_ospf_neighbors_output", 0.27, 0.52)  
    create_textbox_with_scrollbar(root, "network_device_eigrp_neighbors_output", 0.49, 0.52)  
    create_textbox_with_scrollbar(root, "network_device_stp_root_bridge_output", 0.71, 0.52)  

  
    root.progress_bar = ttk.Progressbar(root, orient="horizontal", mode="determinate")
    root.progress_bar.pack(side="bottom", fill="x", pady=10)  

    root.progress_label = ttk.Label(root, text="0%", bootstyle="light")
    root.progress_label.place(relx=0.5, rely=0.93, anchor="center")  

    detect_interfaces(interface_dropdown)

    root.mainloop()

def create_textbox_with_scrollbar(root, name, relx, rely):
    frame = ttk.Frame(root)
    frame.place(relx=relx, rely=rely, anchor="nw")

    text_box = tk.Text(frame, height=5, width=30, padx=5, pady=5)
    text_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_box.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    text_box.config(yscrollcommand=scrollbar.set)

    setattr(root, name, text_box)


def display_interface_info(event, interface_var, mac_label, ipv4_label):
    interface = interface_var.get()
    addrs = psutil.net_if_addrs()[interface]
    mac_address = ""
    ipv4_address = ""

    for addr in addrs:
        if addr.family == psutil.AF_LINK:
            mac_address = addr.address
        elif addr.family == socket.AF_INET:
            ipv4_address = addr.address

    mac_label.config(text=f"MAC Address: {mac_address}")
    ipv4_label.config(text=f"IPv4 Address: {ipv4_address}")

def start_recon(interface_var):
    home_directory = os.path.expanduser("~")
    capture_file = os.path.join(home_directory, "capture.pcap")
    
    # Delete the existing PCAP file if it exists
    if os.path.exists(capture_file):
        os.remove(capture_file)

    selected_interface = interface_var.get()
    if selected_interface:
        # Pass root as an argument to the threads
        threading.Thread(target=capture_and_find_native_vlan, args=(root, selected_interface)).start()
        threading.Thread(target=update_progress_bar, args=(root,)).start()
        threading.Thread(target=find_network_device_names, args=(root, selected_interface)).start()
        threading.Thread(target=find_network_device_models, args=(root, selected_interface)).start()
        threading.Thread(target=find_network_device_ios_versions, args=(root, selected_interface)).start()
        threading.Thread(target=find_network_device_management_ips, args=(root, selected_interface)).start()
        threading.Thread(target=find_network_device_ospf_neighbors, args=(root, selected_interface)).start()
        threading.Thread(target=find_network_device_eigrp_neighbors, args=(root, selected_interface)).start()
        threading.Thread(target=find_network_device_stp_root_bridge, args=(root, selected_interface)).start()

def create_section(root, section_name, x, y):
    section_label = ttk.Label(root, text=section_name, bootstyle="light")
    section_label.place(x=x, y=y, anchor="w")

    output_frame = ttk.Frame(root)
    output_frame.place(x=x, y=y + 25, anchor="w", width=400, height=100)

    output_scrollbar = ttk.Scrollbar(output_frame, orient="vertical")
    output_scrollbar.pack(side="right", fill="y")

    output_text = tk.Text(output_frame, width=50, height=5, wrap="word", background='#1c1c1c', foreground="#ffffff", font=("Helvetica", 12), bd=0, yscrollcommand=output_scrollbar.set)
    output_text.pack(side="left", fill="both", expand=True)

    output_scrollbar.config(command=output_text.yview)
    setattr(root, f"{section_name.lower().replace(' ', '_')}_output", output_text)

def detect_interfaces(interface_dropdown):
    interfaces = psutil.net_if_addrs().keys()
    interface_dropdown['values'] = list(interfaces)
def capture_and_find_native_vlan(root, interface):
    home_directory = os.path.expanduser("~")
    capture_file = os.path.join(home_directory, "capture.pcap")
    capture_command = f"tshark -i {interface} -w {capture_file} 2>/dev/null"  # Redirect stderr to /dev/null
    
    output_text = getattr(root, "native_vlan_output")
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.INSERT, "Native VLAN:\n")
    output_text.yview(tk.END)
    
    try:
        capture_process = subprocess.Popen(capture_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = capture_process.communicate(timeout=90)
        capture_process.wait()  

        if stderr:
            output_text.insert(tk.INSERT, stderr.decode())
            output_text.yview(tk.END)

        # Explicitly terminate the process
        capture_process.terminate()

        # Ensure the PCAP file is present before proceeding
        if os.path.exists(capture_file):
            # Add delay to ensure PCAP file is fully written
            time.sleep(2)
            find_native_vlan(root, interface)
            find_network_device_names(root, interface)
            find_network_device_models(root, interface)
            find_network_device_ios_versions(root, interface)
            find_network_device_management_ips(root, interface)
            find_network_device_ospf_neighbors(root, interface)
            find_network_device_eigrp_neighbors(root, interface)
            find_network_device_stp_root_bridge(root, interface)
        else:
            output_text.insert(tk.INSERT, "PCAP file not found.\n")
            output_text.yview(tk.END)
    except subprocess.TimeoutExpired:
        capture_process.terminate()
        output_text.yview(tk.END)
        if os.path.exists(capture_file):
            time.sleep(2)
            find_native_vlan(root, interface)
            find_network_device_names(root, interface)
            find_network_device_models(root, interface)
            find_network_device_ios_versions(root, interface)
            find_network_device_management_ips(root, interface)
            find_network_device_ospf_neighbors(root, interface)
            find_network_device_eigrp_neighbors(root, interface)
            find_network_device_stp_root_bridge(root, interface)
    except Exception as e:
        output_text.insert(tk.INSERT, str(e))
        output_text.yview(tk.END)


def find_native_vlan(root, interface):
    home_directory = os.path.expanduser("~")
    capture_file = os.path.join(home_directory, "capture.pcap")
    read_command = f"tshark -r {capture_file} -T fields -e cdp.native_vlan | sort | uniq" 
    try:
        with open(os.devnull, 'w') as devnull:
            process = subprocess.Popen(read_command, shell=True, stdout=subprocess.PIPE, stderr=devnull)
            stdout, _ = process.communicate()
        output_text = getattr(root, "native_vlan_output")
        output_text.delete(1.0, tk.END)
        if stdout:
            output_text.insert(tk.INSERT, "Native VLAN:\n" + stdout.decode())
            output_text.yview(tk.END)
    except Exception as e:
        output_text = getattr(root, "native_vlan_output")
        output_text.insert(tk.INSERT, "Native VLAN:\n" + str(e))
        output_text.yview(tk.END)
def find_network_device_names(root, interface):
    home_directory = os.path.expanduser("~")
    capture_file = os.path.join(home_directory, "capture.pcap")
    
    # Wait for the file to exist with a timeout
    timeout = 90  
    while timeout > 0:
        if os.path.exists(capture_file):
            break
        time.sleep(1)
        timeout -= 1

    if not os.path.exists(capture_file):
        output_text = getattr(root, "network_device_names_output")
        output_text.insert(tk.INSERT, "Network Device Names:\nPCAP file not found after waiting period.\n")
        output_text.yview(tk.END)
        return

    read_command = f"tshark -r {capture_file} -T fields -e cdp.deviceid | sort | uniq"  
    try:
        with open(os.devnull, 'w') as devnull:
            process = subprocess.Popen(read_command, shell=True, stdout=subprocess.PIPE, stderr=devnull)
            stdout, _ = process.communicate()

        output_text = getattr(root, "network_device_names_output")
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.INSERT, "Network Device Names:\n")
        if stdout:
            output_text.insert(tk.INSERT, stdout.decode())
            output_text.yview(tk.END)
    except Exception as e:
        output_text = getattr(root, "network_device_names_output")
        output_text.insert(tk.INSERT, "Network Device Names:\n" + str(e))
        output_text.yview(tk.END)

def find_network_device_models(root, interface):
    home_directory = os.path.expanduser("~")
    capture_file = os.path.join(home_directory, "capture.pcap")

    # Wait for the file to exist with a timeout
    timeout = 90  
    while timeout > 0:
        if os.path.exists(capture_file):
            break
        time.sleep(1)
        timeout -= 1

    if not os.path.exists(capture_file):
        output_text = getattr(root, "network_device_models_output")
        output_text.insert(tk.INSERT, "Network Device Models:\nPCAP file not found after waiting period.\n")
        output_text.yview(tk.END)
        return

    read_command = f"tshark -r {capture_file} -T fields -e cdp.platform | sort | uniq"  
    try:
        with open(os.devnull, 'w') as devnull:
            process = subprocess.Popen(read_command, shell=True, stdout=subprocess.PIPE, stderr=devnull)
            stdout, _ = process.communicate()
        
        output_text = getattr(root, "network_device_models_output")
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.INSERT, "Network Device Models:\n")
        
        if stdout:
            output_text.insert(tk.INSERT, stdout.decode())
            output_text.yview(tk.END)
    except Exception as e:
        output_text = getattr(root, "network_device_models_output")
        output_text.insert(tk.INSERT, "Network Device Models:\n" + str(e))
        output_text.yview(tk.END)

def find_network_device_ios_versions(root, interface):
    home_directory = os.path.expanduser("~")
    capture_file = os.path.join(home_directory, "capture.pcap")
    
    # Wait for the file to exist with a timeout
    timeout = 90  
    while timeout > 0:
        if os.path.exists(capture_file):
            break
        time.sleep(1)
        timeout -= 1

    if not os.path.exists(capture_file):
        output_text = getattr(root, "network_device_ios_versions_output")
        output_text.insert(tk.INSERT, "Network Device IOS Versions:\n\nPCAP file not found after waiting period.\n")
        output_text.yview(tk.END)
        return

    read_command = f"tshark -r {capture_file} -T fields -e cdp.software_version | sort | uniq | grep --color=never -oP 'Version \\K[^,]+'"
    try:
        with open(os.devnull, 'w') as devnull:
            process = subprocess.Popen(read_command, shell=True, stdout=subprocess.PIPE, stderr=devnull)
            stdout, _ = process.communicate()
        output_text = getattr(root, "network_device_ios_versions_output")
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.INSERT, "Network Device IOS Versions:\n\n")
        if stdout:
            output_text.insert(tk.INSERT, stdout.decode())
            output_text.yview(tk.END)
    except Exception as e:
        output_text = getattr(root, "network_device_ios_versions_output")
        output_text.insert(tk.INSERT, "Network Device IOS Versions:\n\n" + str(e))
        output_text.yview(tk.END)

def find_network_device_management_ips(root, interface):
    home_directory = os.path.expanduser("~")
    capture_file = os.path.join(home_directory, "capture.pcap")
    
    # Wait for the file to exist with a timeout
    timeout = 90  
    while timeout > 0:
        if os.path.exists(capture_file):
            break
        time.sleep(1)
        timeout -= 1

    if not os.path.exists(capture_file):
        output_text = getattr(root, "network_device_management_ips_output")
        output_text.insert(tk.INSERT, "Network Device Management IPs:\n\nPCAP file not found after waiting period.\n")
        output_text.yview(tk.END)
        return

    read_command = f"tshark -r {capture_file} -T fields -e cdp.nrgyz.ip_address | sort | uniq | grep --color=never -oP '^\\d{{1,3}}(\\.\\d{{1,3}}){{3}}'"
    try:
        with open(os.devnull, 'w') as devnull:
            process = subprocess.Popen(read_command, shell=True, stdout=subprocess.PIPE, stderr=devnull)
            stdout, _ = process.communicate()
        output_text = getattr(root, "network_device_management_ips_output")
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.INSERT, "Network Device Management IPs:\n\n")
        if stdout:
            output_text.insert(tk.INSERT, stdout.decode())
            output_text.yview(tk.END)
    except Exception as e:
        output_text = getattr(root, "network_device_management_ips_output")
        output_text.insert(tk.INSERT, "Network Device Management IPs:\n\n" + str(e))
        output_text.yview(tk.END)

def find_network_device_ospf_neighbors(root, interface):
    home_directory = os.path.expanduser("~")
    capture_file = os.path.join(home_directory, "capture.pcap")
    
    # Wait for the file to exist with a timeout
    timeout = 90  
    while timeout > 0:
        if os.path.exists(capture_file):
            break
        time.sleep(1)
        timeout -= 1

    if not os.path.exists(capture_file):
        output_text = getattr(root, "network_device_ospf_neighbors_output")
        output_text.insert(tk.INSERT, "Network Device OSPF Neighbors:\nPCAP file not found after waiting period.\n")
        output_text.yview(tk.END)
        return

    read_command = f"tshark -r {capture_file} -Y ospf.hello -T fields -e ip.src | sort | uniq"
    try:
        with open(os.devnull, 'w') as devnull:
            process = subprocess.Popen(read_command, shell=True, stdout=subprocess.PIPE, stderr=devnull)
            stdout, _ = process.communicate()
        output_text = getattr(root, "network_device_ospf_neighbors_output")
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.INSERT, "Network Device OSPF Neighbors:\n \n")
        if stdout:
            output_text.insert(tk.INSERT, stdout.decode())
            output_text.yview(tk.END)
    except Exception as e:
        output_text = getattr(root, "network_device_ospf_neighbors_output")
        output_text.insert(tk.INSERT, "Network Device OSPF Neighbors:\n" + str(e))
        output_text.yview(tk.END)

def find_network_device_eigrp_neighbors(root, interface):
    home_directory = os.path.expanduser("~")
    capture_file = os.path.join(home_directory, "capture.pcap")
    
    # Wait for the file to exist with a timeout
    timeout = 90  
    while timeout > 0:
        if os.path.exists(capture_file):
            break
        time.sleep(1)
        timeout -= 1

    if not os.path.exists(capture_file):
        output_text = getattr(root, "network_device_eigrp_neighbors_output")
        output_text.insert(tk.INSERT, "Network Device EIGRP Neighbors:\nPCAP file not found after waiting period.\n")
        output_text.yview(tk.END)
        return

    read_command = f"tshark -r {capture_file} -Y 'eigrp && eigrp.opcode == 5' -T fields -e ip.src | sort | uniq"
    try:
        with open(os.devnull, 'w') as devnull:
            process = subprocess.Popen(read_command, shell=True, stdout=subprocess.PIPE, stderr=devnull)
            stdout, _ = process.communicate()
        output_text = getattr(root, "network_device_eigrp_neighbors_output")
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.INSERT, "Network Device EIGRP Neighbors:\n \n")
        if stdout:
            output_text.insert(tk.INSERT, stdout.decode())
            output_text.yview(tk.END)
    except Exception as e:
        output_text = getattr(root, "network_device_eigrp_neighbors_output")
        output_text.insert(tk.INSERT, "Network Device EIGRP Neighbors:\n" + str(e))
        output_text.yview(tk.END)

def find_network_device_stp_root_bridge(root, interface):
    home_directory = os.path.expanduser("~")
    capture_file = os.path.join(home_directory, "capture.pcap")
    
    # Wait for the file to exist with a timeout
    timeout = 90  
    while timeout > 0:
        if os.path.exists(capture_file):
            break
        time.sleep(1)
        timeout -= 1

    if not os.path.exists(capture_file):
        output_text = getattr(root, "network_device_stp_root_bridge_output")
        output_text.insert(tk.INSERT, "Network Device STP Root Bridge:\nPCAP file not found after waiting period.\n")
        output_text.yview(tk.END)
        return

    read_command = f"tshark -r {capture_file} -T fields -e stp.root.prio | sort | uniq"
    try:
        with open(os.devnull, 'w') as devnull:
            process = subprocess.Popen(read_command, shell=True, stdout=subprocess.PIPE, stderr=devnull)
            stdout, _ = process.communicate()
        output_text = getattr(root, "network_device_stp_root_bridge_output")
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.INSERT, "Network Device STP Root Bridge:\n")
        if stdout:
            output_text.insert(tk.INSERT, stdout.decode())
            output_text.yview(tk.END)
    except Exception as e:
        output_text = getattr(root, "network_device_stp_root_bridge_output")
        output_text.insert(tk.INSERT, "Network Device STP Root Bridge Priority:\n" + str(e))
        output_text.yview(tk.END)

def update_progress_bar(root):
    for i in range(90):
        time.sleep(1)
        percentage = int((i + 1) / 90 * 100)
        root.progress_bar["value"] = percentage
        root.progress_label.config(text=f"{percentage}%")
        root.update_idletasks()


main_menu()
