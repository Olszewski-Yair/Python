from scapy.all import *
from scapy.layers.inet import *
import logging


def CastomTCP():

    open_ports = []

    target = input("Please Enter Target IP:\n")
    startport = (int(input("PLease Enter First port for scanning range\n")))
    endport = (int(input("please enter last port for scanning range\n")))
    print(f'scanning +{target}+ for open TCP ports \n')

    try:
        for port in range(startport, endport):
            packet = IP(dst=target)/TCP(dport=port, flags='S')
            response = sr1(packet, verbose=0, timeout=5)
#           print(response)
            if response is not None:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 'SA':
                    print('port '+str(port)+' is open')
                    open_ports.append(port)
                    send(IP(dst=target) / TCP(dport=response.sport, flags='A'), verbose=0)
                    send(IP(dst=target) / TCP(dport=response.sport, flags='R'), verbose=0)
                    logging.info("Scan complete")
            else:
                pass

    except (AttributeError, Scapy_Exception) as e:
        logging.error(f"An error occurred: {e}")

    print(open_ports)


def TOP10tcp():

    open_ports = []

    target = input("Please Enter Target IP:\n")
    print(f'scanning +{target}+ for open TCP ports \n')

    try:
        for port in [80, 443, 21, 22, 25, 53, 23, 465, 143, 8080]:

            packet = IP(dst=target) / TCP(dport=port, flags='S')
            response = sr1(packet, verbose=0, timeout=5)
            #           print(response)
            if response is not None:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 'SA':
                    open_ports.append(port)
                    send(IP(dst=target) / TCP(dport=response.sport, flags='A'), verbose=0)
                    send(IP(dst=target) / TCP(dport=response.sport, flags='R'), verbose=0)
                    logging.info("Scan complete\n\n")
            else:
                pass

    except (AttributeError, Scapy_Exception) as e:
        logging.error(f"An error occurred: {e}")

    print(open_ports)


def CastomUDP():

    open_ports = []

    target = input("Please Enter Target IP:\n")
    startport = (int(input("PLease Enter Fist port for scanning range\n")))
    endport = (int(input("please enter last port for scanning range\n")))
    print(f'scanning +{target}+ for open UDP ports \n')

    try:
        for port in range(startport, endport):
            packet = IP(dst=target) / UDP(dport=port)
            response = sr1(packet, verbose=0, timeout=5)
#           print(response)
            if response is not None:
                if response.haslayer(UDP):
                    print('port ' + str(port) + ' is open')
                    open_ports.append(port)
                logging.info("Scan complete\n\n")
            else:
                pass

    except (AttributeError, Scapy_Exception) as e:
        logging.error(f"An error occurred: {e}")

    print(open_ports)


def TopUDP():

    open_ports = []

    target = input("Please Enter Target IP:\n")
    print(f'scanning +{target}+ for open UDP ports \n')

    try:
        for port in [53, 67, 69, 161, 162, 123, 514]:
            packet = IP(dst=target) / UDP(dport=port)
            response = sr1(packet, verbose=0, timeout=5)
            #           print(response)
            if response is not None:
                if response.haslayer(UDP):
                    print('port ' + str(port) + ' is open')
                    open_ports.append(port)
                    logging.info("Scan complete\n\n")
            else:
                pass

    except (AttributeError, Scapy_Exception) as e:
        logging.error(f"An error occurred: {e}")

    print(open_ports)


def Combi():

    ports = []

    target = input("Please Enter Target IP:\n")
    print(f'scanning +{target}+ for open TCP/UDP ports \n')

    try:
        for port in [80, 443, 21, 22, 25, 53, 23, 465, 143, 8080, 67, 69, 161, 162, 123, 514]:

            packet = IP(dst=target) / TCP(dport=port, flags='S')
            packet2 = IP(dst=target) / UDP(dport=port,)
            response = sr1(packet, verbose=0, timeout=5)
            response2 = sr1(packet2, verbose=0, timeout=5)
            #           print(response)
            if response is not None:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 'SA':
                    send(IP(dst=target) / TCP(dport=response.sport, flags='A'), verbose=0)
                    send(IP(dst=target) / TCP(dport=response.sport, flags='R'), verbose=0)
                    ports.append(port)
                    logging.info("Scan complete")

                if response2 is not None:
                    if response.haslayer(UDP):
                        print('port ' + str(port) + ' is open')
                        ports.append(port)
                        logging.info("Scan complete\n\n")

            else:
                pass

    except (AttributeError, Scapy_Exception) as e:
        logging.error(f"An error occurred: {e}")

    print(ports)


def selection():

    a = (int(input("TO SCAN TCP PORTS PRESS: 1 \nTo scan UDP ports PRESS: 2\nTo scan combination PRESS:3\n\n")))
    if a == 3:
        Combi()
    else:
        pass
        if a == 1 or 2:
            b = (int(input("\nTo scan TOP ports PRESS:2\nTo scan CASTOM set PRESS:3\n")))
            if a == 1 and b == 2:
                TOP10tcp()
            elif a == 1 and b == 3:
                CastomTCP()
            elif a == 2 and b == 2:
                TopUDP()
            elif a == 2 and b == 3:
                CastomUDP()

        else:
            pass


print("HELLO !\n")
selection()
