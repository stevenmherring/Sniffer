import re
results = "search_results.log" #out log for search packets
writePacket = False #flag
#read the dump line by line, recreating each individual packet by the
#Packet Number:
#if any line contains the regex/term, set a flag
#if flag is true we write the entire packet
def searchPackets(infile, term, packetID):
    idlength = len(packetID)
    try:
        outfile = open(results, "w")
    except IOError as err:
        print (str(err))
        return False
    try:
        with open(infile) as f:
            currentPacket = ""
            for line in f:
                checkLine = packetID[:idlength]
                if packetID == checkLine:
                    #start of a new packet
                    #check if former packet held search term
                    if currentPacket != "" and bool(re.search(term, currentPacket)):
                        try:
                            outfile.write(currentPacket + "\n")
                        except IOError as err:
                            print (str(err))
                    #start recording next packet
                    currentPacket = line
                else:
                    currentPacket = currentPacket + "\n" + line #append line onto currentPacket
    except IOError as err:
        print (str(err))
        try:
            outfile.close()
        except IOError as err:
            print (str(err))
        return False

    try:
        outfile.close()
    except IOError as err:
        print (str(err))
    return True
