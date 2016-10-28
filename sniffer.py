import sys
import socket
import os
import errno
import getopt
import parseTools
import searchTools
from struct import *
import time

#dev info
version = "0.0.1"
authors = "Steven Herring"
usecase = "Sniff, log, parse and search packets during a given period of time"

#string usage
err_socket_failure = "Failure to create or use socket"
err_fopen_failure = "Failed to open file"
err_parsing = "Parsing Failure Please refer to STDOUT/STDERR"
err_search = "Search Function Failure"

#globals
reconstruct = False
outfile = "dump.log"
tempfile = "temp.log"
search = ""
period = 10
device = "" #remove, we can just sniff everything
packet_number = 0
WINDOWS_NAME = "nt"
packetID = "Packet Number: "

def usage ():
    print ("Packet Sniffer & Parser by %s." % authors)
    print (usecase)
    print ("Version: %s" % version)
    print
    print ("Usage: sniffer.py -o outfile -t time [-rhs:]")
    print ("-o outfile   - Dump file for packets. Default dump.log")
    print ("-t time      - Time to parse in s. Default 10s")
    print ("-r           - Reconstruct HTTP and DNS packets")
    print ("-h           - Print usage")
    print ("-s term      - Search outfile for term or regex")
    sys.exit(0)

def deleteFile(filename):
    try:
        os.remove(filename)
    except OSError as err:
        if err.errno != errno.ENOENT:
            raise

def main():
    # global copies
    global reconstruct
    global outfile
    global search
    global period
    global tempfile
    global packet_number

    #if not len(sys.argv[1:]): # if no arguments, we're not doing anything
    #    usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:],"o:t:s:rh",["output","time","search","reconstruct","help"])
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
            period = float(a)
        elif o in ("-s", "--search"):
            search = a

    try:
        #s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        #if windows, protocol is IP, unix ICMP
        if os.name == WINDOWS_NAME:
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.ntohs(0x0003)
        #still unsure if this is the correct socket configuration, as I can't test yet
        #need to get some time to a windows/linux box to test everything, but my research suggests
        #this is correct.
        #sniffSocket = socket.socket(socket.AF_INET , socket.SOCK_RAW , socket_protocol)
        sniffSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW , socket_protocol)
        #bind bind all sockets
        #sniffSocket.bind(("",0))
        #include IP headers, unsure if necessary ATM
        #sniffSocket.setsockopt(socket.IPPOTO_IP, socket.IP_HDRINCL, 1)
        #if windows, enable promiscuous
        if os.name == WINDOWS_NAME:
            sniffSocket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except socket.error as err:
        print (err_socket_failure)
        print (str(err))
        sys.exit(0)

    #clean up files from possible previous parse.
    #not catching errors, don't care if files dont exist for now
    deleteFile(outfile)
    deleteFile(outfile + ".bak")
    deleteFile(tempfile)

    #open dump file
    try:
        f = open(outfile, "w")
    except IOError as err:
        print (err_fopen_failure)
        print (str(err))
        sys.exit(0)
    stoptime = time.time() + period
    print (stoptime)
    #TODO perhaps spawn new thread to manage time, as program will wait sniffing
    #BEGIN PACKET PARSE
    while True:
        print (time.time())
        if time.time() > stoptime: # if we ran past provided time
            break
        packet = sniffSocket.recvfrom(65565) #receive packet
        packet = packet[0] #pull packet from tuple
        print(packetID + str(packet_number) + "\n")
        f.write(packetID + str(packet_number) + "\n")
        packet_number += 1
        if(parseTools.initPacketParse(packet, f) == False):
            #we returned false through an error, break and terminate gracefully
            print (err_parsing)
            break
    #END PACKET PARSE
    #if windows, disable promiscuous
    if os.name == WINDOWS_NAME:
        sniffSocket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    #if reconstruct option select
    if reconstruct:
        #go through parsed packets, combine packets.
        if(parseTools.reconstructPackets(tempfile) == False):
            print (err_reconstruct)
        else:
            #when done, move original parse to .bak location
            #move reconstructed packets to dump
            try:
                os.rename(outfile, outfile + ".bak")
            except OSError as err:
                print(str(err))
            try:
                os.rename(tempfile, outfile)
            except OSError as err:
                print(str(err))


    #if search selected
    if search != "":
        search_file = outfile
        #if we reconstructed, original dump will be at dump.log.bak
        if reconstruct:
            search_file = outfile + ".bak"
        #search by packet for REGEX...packets tracked by "Packet Number: " + packet_number
        if(searchTools.searchPackets(search_file, search, packet) == False):
            print (err_search)
    #end program sequence
    try:
        f.close()
    except IOError as err:
        print (str(err))
    sys.exit(0)


#call main
main()
