results = "search_results.log" #out log for search packets
writePacket = False #flag
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
                    if writePacket == True:
                        try:
                            outfile.write(currentPacket + "\n")
                        except IOError as err:
                            print (str(err))
                    #start recording next packet
                    currentPacket = line
                    #set flag back to flase
                    writePacket = False
                elif bool(re.search(term, line)):
                    #packet has search term, mark as such
                    writePacket = True
                    currentPacket = currentPacket + "\n" + line #append line onto currentPacket
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
