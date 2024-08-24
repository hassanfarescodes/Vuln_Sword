### LIBRARIES ###
import nmap
import os
import time
import sys
import socket
import threading  
#################


####### COLORS AND SYMBOLS #######
CM = '\u2713'                    # Check Tick
B_GREEN = '\033[32;1;40m'        # Bright Green
B_RED = '\033[38;5;196;1m'       # Bright Red
B_ORANGE = '\033[38;5;208;1m'    # Bright Orange
B_PURPLE = '\033[38;5;165;1m'    # Bright Purple
L_PINK = '\033[38;5;207m'        # Light Pink
B_BLUE = '\033[38;5;123m'        # Bright_Blue 
TERM_GREEN = '\033[38;2;0;255;0m'# Terminal Green
B_CYAN = '\033[38;2;0;255;255m'  # Bright Cyan
WHITE = '\033[97m'               # White
RESET = '\033[0m'                # Reset
##################################


#################################### INITIALIZATION #####################################
def typer(text, color, delay=0.01):
    """
    Purpose: outputs string in a specific color in a typing-out like font
    --------

    Parameters: 
    -----------
    text : String type, text to be typed
    color : Color from COLORS AND SYMBOLS
    delay : Delay between each character in seconds
    """
    print(color, end='')
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print(RESET) # Reset Font


def rotating_loader(stop_event, delay=0.1):
    """
    Purpose: Displays a loading animation
    --------

    Parameters:
    -----------
    stop_event : An event that controls when to stop the rotating_loader
    delay : Time in seconds between each animation change
    """
    print(B_ORANGE, end = '')
    chars = "/-\\|"  # Characters to display in sequence
    while not stop_event.is_set():
        for char in chars:
            sys.stdout.write(f'\r[{char}] Scanning for open ports')
            sys.stdout.flush()
            time.sleep(delay)
            if stop_event.is_set():
                break
    print(f'\r{B_GREEN}[{CM}] Scan complete!                \n')  # Clear the loader

os.system("clear")
ascii_art = f"""{B_RED} 
 ______________________________________________________|_._._._._._._._._._.
 \\________________V_u_l_n____S_w_o_r_d_________________|_#_#_#_#_#_#_#_#_#_|
                                                       l
                                                           {TERM_GREEN}-Scan responsibly! 
|Vuln Sword 1.0.0|{B_RED}                                          
"""
typer(ascii_art, RESET, 0.0008)   # Types out the ascii art
#########################################################################################



#################################### FUNCTIONS AND SCRIPTS ########################################
def scan_ip(ip_address): 
    """
    Purpose: Scans IP address for open ports and banners (Also displays them)
    --------

    Parameters:
    -----------
    ip_address : String of the IP address to scan

    Returns: 
    --------
    services : String type, detected services
    open_ports : Int type, open ports
    banners : String type, detected banners
    """
    stop_event = threading.Event()  # Event to stop the loader
    loader_thread = threading.Thread(target=rotating_loader, args=(stop_event,))
    loader_thread.start()  # Start the loader

    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments='-sV')

    stop_event.set()  # Stop the loader
    loader_thread.join()  # Wait for the loader to finish

    services = []
    open_ports = []
    banners = {}  # Dictionary to store banners for each port

    print(B_PURPLE, end = '')
    # First, scan and display open ports and services
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port]['version']
                services.append(f"{service} {version}")
                open_ports.append(port)
                print(f"Port: {port}\tService: {service}\tVersion: {version}")
    print(WHITE + "-" * 65, end = '')

    # Then, grab banners for each open port

    print(L_PINK)
    for port in open_ports:
        banner = grab_banner(ip_address, port)
        if banner:
            banners[port] = banner
            print(f"Banner on port {port}: {banner}")

    print(RESET)
    return services, open_ports, banners


def prompt_gobuster(ip_address, domain): 
    """
    Purpose: Prompts the user to perform a gobuster scan
    --------

    Parameters:
    -----------
    ip_address : String type, IP address to scan
    domain: String type, domain of the website to scan for subdomains
    """
    run_gobuster = input(f"{B_GREEN}[*] Port 80 detected! {B_BLUE}Run a gobuster scan to find possible subdomains? (y/n): ").lower()
    if run_gobuster == 'y':
        menu = """
[1] Small
[2] Medium
[3] Large
[4] XLarge\n
        """
        typer(menu, WHITE, 0.02)
        choice = input("[*] Enter the size of wordlist: ")
        if choice == "1":
            wordlist = "bruteforce/small.txt"
        elif choice == "2":
            wordlist = "bruteforce/medium.txt"
        elif choice == "3":
            wordlist = "bruteforce/large.txt"
        elif choice == "4":
            wordlist = "bruteforce/xlarge.txt"
        else:
            print("[!] Invalid Choice Detcted!")
        gobuster_scan(ip_address, wordlist, domain)
    else:
        typer("[!] Skipping...", B_RED, 0.02)


def gobuster_scan(ip_address, wordlist, domain):
    """
    Purpose: Executes the gobuster scan
    --------

    Parameters:
    -----------
    ip_address : String type, IP address to scan
    wordlist : String type, path for the wordlist used to bruteforce subdomains
    domain : String type, domain of the website to scan for subdomains
    """
    typer("[!] Running gobuster scan...", B_ORANGE)
    gobuster_command = f"gobuster dir -u http://{domain} -w {wordlist}"
    os.system(gobuster_command)
    typer("[!] Gobuster scan finished!", B_GREEN)


def search_exploits(service): 
    """
    Purpose: Searches for exploits for a specific service
    --------

    Parameters:
    -----------
    service : String type, Service to scan
    """
    search_command = f"searchsploit {service}"
    os.system(search_command)
    print(RESET)


def grab_banner(ip_address, port): 
    """
    Purpose: Gets the banner
    --------

    Parameters:
    -----------
    ip_address : String type, IP address to grab banner from
    port: Int type, port to grab banner from

    Returns:
    --------
    banner : String type, banner found
    None : If error occurs
    """
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip_address, port))
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')  # Common banner grabbing request
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner  # Return the grabbed banner
    except Exception as e:
        typer(f"[!] Failed to grab banner on port {port}. Error: {e}", B_RED)
        return None


def extract_domain_from_banner(banner): 
    """
    Purpose: Extracts domain from banner if available
    --------

    Parameters:
    -----------
    banner : String type, banner to extract domain from

    Returns:
    --------
    domain : String type, name of domain
    None : None type, if no domain is found
    """
    if banner and 'http' in banner:
        parts = banner.split()
        for part in parts:
            if part.startswith('http://') or part.startswith('https://'):
                domain = part.split('/')[2]
                return domain
    return None


def modify_hosts_file(ip_address, domain): 
    """
    Purpose: Modifies the /etc/hosts file to familiarize system with domain
    --------
    Parameters:
    -----------
    ip_address : String type, IP address of domain
    domain : String type, name of the domain
    """
    # Prompt user for confirmation
    confirmation = input(f"\n{B_BLUE}[*] Do you want to add the following entry to your /etc/hosts file: {WHITE} {ip_address}    {domain} {B_BLUE}| (y/n) >> " + RESET).lower()
    
    if confirmation == 'y':
        try:
            # Open the /etc/hosts file for appending
            with open('/etc/hosts', 'a') as hosts_file:
                hosts_file.write(f"{ip_address}    {domain}\n")
            typer("[!] Successfully added entry to /etc/hosts.", B_GREEN)
        except PermissionError:
            typer("[!] Permission denied. You need to run this script as root.", B_RED)
        except Exception as e:
            typer(f"[!] Failed to modify /etc/hosts. Error: {e}", B_RED)
    else:
        typer("[!] Skipping modification of /etc/hosts...", B_RED, 0.02)


def main(): 
    """
    Purpose: Connects all the functions to prepare for execution
    --------
    """
    ip_address = input(f"{B_BLUE}[*] Enter the IP address to scan: {B_RED}")
    services, open_ports, banners = scan_ip(ip_address)

    for service in services:
        typer(f"[!] Searching for exploits related to: {service}\n", B_ORANGE)
        search_exploits(service)

    # Check if port 80 was detected and prompt for gobuster after exploit search
    if 80 in open_ports and 80 in banners:
        domain = extract_domain_from_banner(banners[80])
        prompt_gobuster(ip_address, domain)

    # Check if a web service was detected and prompt to modify /etc/hosts
        if domain:
            modify_hosts_file(ip_address, domain)
        else:
            typer("[!] No website detected or unable to extract domain from the banner.", B_RED)
    else:
        typer("[!] No banners detected on port 80.", B_RED)

    typer("[" + str(CM) + "] SCANS FINISHED!", B_GREEN, 0.03)
    typer("\nGOODBYE!", TERM_GREEN, 0.12)


###################################################################################################


# Main Function / Execution #
if __name__ == "__main__":
    main()
#############################
