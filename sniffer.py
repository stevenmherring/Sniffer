import sys
import socket
import os
import getopt
import parseTools
from struct import *
import time
import pcapy

#dev info
version = "0.0.1"
authors = "Steven Herring, Thomas Karnati, Himanshu Kattelu"
usecase = "Sniff, log, parse and search packets during a given period of time"

#string usage
err_socket_failure = "Failure to create or use socket"
err_fopen_failure = "Failed to open file"
err_parsing = "Parsing Failure Please refer to STDOUT/STDERR"

#globals
reconstruct = False
outfile = "dump.log"
search = ""
period = 10
device = "" #remove, we can just sniff everything
packet_number = 0
WINDOWS_NAME = "nt"

def usage ():
    print ("Packet Sniffer & Parser by %s." % authors)
    print (usecase)
    print ("Version: %s" % version)
    print
    print ("Usage: sniffer.py -o outfile -t time [-rhs:d:]")
    print ("-o outfile   - Dump file for packets. Default dump.log")
    print ("-t time      - Time to parse in s. Default 10s")
    print ("-r           - Reconstruct HTTP and DNS packets")
    print ("-h           - Print usage")
    print ("-d device    - **UNSUPPORTED** Define device to sniff, default is en0")
    print ("-s term      - Search outfile for term or regex")
    sys.exit(0)

def main():
    # global copies
    global reconstruct
    global outfile
    global search
    global period
    global device

    if not len(sys.argv[1:]): # if no arguments, we're not doing anything
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:],"o:t:s:rhd:",["output","time","search","reconstruct","help","device"])
    except getopt.GetoptError as err:
        print( str(err) );
        usage()

    for o,a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-r", "--reconstruct"):
            reconstruct = True
        elif o in ("-o", "--output"):
            outfile = a
        elif o in ("-t", "--time"):
            period = a
        elif o in ("-s", "--search"):
            search = a
        elif o in ("-d", "--device"):
            print ("Device support not implemented")
            break
            devices = pcapy.findalldevs()
            if a in devices:
                device = a
            else:
                print ("Device not available. Available devices are...")
                for d in devices:
                    print (d)
                sys.exit(0)

    try:
        #s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        #if windows, protocol is IP, unix ICMP
        if os.name == WINDOWS_NAME:
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        #still unsure if this is the correct socket configuration, as I can't test yet
        #need to get some time to a windows/linux box to test everything, but my research suggests
        #this is correct.
        #sniffSocket = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        sniffSocket = socket.socket(socket.AF_INET , socket.SOCK_RAW , socket_protocol)
        #bind bind all sockets
        sniffSocket.bind(("",0))
        #include IP headers, unsure if necessary ATM
        sniffSocket.setsockopt(socket.IPPOTO_IP, socket.IP_HDRINCL, 1)
        #if windows, enable promiscuous
        if os.name == WINDOWS_NAME:
            sniffSocket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except socket.error as err:
        print (err_socket_failure)
        print (str(err))
        sys.exit(0)

    try:
        f = open(outfile)
    except IOError as err:
        print (err_fopen_failure)
        print (str(err))
        sys.exit(0)
    stoptime = time.time() + period
    while True:
        if time.time() > stoptime: # if we ran past provided time
            break
        packet = sniffSocket.recvfrom(65565) #receive packet
        packet = packet[0] #pull packet from tuple
        print("Packet Number: " + packet_number)
        f.write("Packet Number: " + packet_number)
        packet_number += 1
        if(parseTools.init_packet_parse(packet, f) == False):
            #we returned false through an error, break and terminate gracefully
            print (err_parsing)
            break
    #if windows, disable promiscuous
    if os.name == WINDOWS_NAME:
        sniffSocket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    try:
        f.close()
    except IOError as err:
        print (str(err))
    sys.exit(0)


#call main
main()
