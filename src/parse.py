###################################################
# William Lam's Wireshark log file parser
# Student Number: 040871728
# Professor: Risvan Coskun
# Course: CST8108
# Language: Python 3
###################################################

# Imports
import os, sys, csv, in_place

inputFile = "SkypeIRC.cap"
outputCSVFile = "output.csv"
outputCSVFile_Handshakes = "output_handshakes.csv"
outputResultsFile = "results.txt"

if (len(sys.argv) > 2):
    sys.exit("If running from the command line, please input 1 additional argument.\nProper command is: python parse.py <pcapngInputFile>")

if (len(sys.argv) == 2):
    inputFile = sys.argv[1]

# TShark terminal command to parse the .pcapng file and output the desired results into a .csv file
outputCmd = "tshark -r " + inputFile + " -T fields -e frame.number -e eth.src -e eth.dst -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Info -E header=y -E separator=,  > " + outputCSVFile

# TShark terminal command with custom filter for correctly identifying handshakes
outputCmd_Handshake = "tshark -r " + inputFile + " -Y \"(tcp.flags.ack==1 || tcp.flags.syn==1 || tcp.flags.fin==1) && (tcp.port==80 || udp.port==80)\" -T fields -e frame.number -e eth.src -e eth.dst -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Info -E header=y -E separator=,  > " + outputCSVFile_Handshakes

# Execute the TShark commands in the system terminal
os.system(outputCmd)
os.system(outputCmd_Handshake)

# Important statistics to keep track of
iteratorIndex = 0
frameCount = 0
httpFrameCount = 0
dnsFrameCount = 0
tcpFrameCount = 0
arpFrameCount = 0
udpFrameCount = 0
icmpFrameCount = 0
num3WayHandshakes = 0
numTerminationHandshakes = 0
finAckCounter = 0

listOf3WayHandshakes = []
listOfTerminationHandshakes = []

# Process the .csv file so that [SYN, ACK] and [FIN, ACK] are displayed properly in .csv (since that string actually have commas in them)

# in_place module handles the logistics of creating, managing and deleting temporary files when performing read and write operations to a file at the same time
with in_place.InPlace(outputCSVFile) as file:
    for line in file:
        line = line.replace('[SYN, ACK]', '[SYN | ACK]', 1)
        line = line.replace('[FIN, ACK]', '[FIN | ACK]', 1)
        file.write(line)
    file.close()

with in_place.InPlace(outputCSVFile_Handshakes) as file:
    for line in file:
        line = line.replace('[SYN, ACK]', '[SYN | ACK]', 1)
        line = line.replace('[FIN, ACK]', '[FIN | ACK]', 1)
        file.write(line)
    file.close()

print("")
print("Table successfully constructed in " + outputCSVFile)
print("")

# Read the main .csv file and parse that for specifics
with open(outputCSVFile, "r") as file:
    reader = csv.reader(file, delimiter=',')
    header = enumerate(reader)
    
    for row in reader:        
        # Increase count of the appropriate protocol frame types
        if (row[5] == "HTTP"):
            httpFrameCount += 1
        if (row[5] == "DNS"):
            dnsFrameCount += 1
        if (row[5] == "TCP"):
            tcpFrameCount += 1
        if (row[5] == "ARP"):
            arpFrameCount += 1
        if (row[5] == "UDP"):
            udpFrameCount += 1
        if (row[5] == "ICMP"):
            icmpFrameCount += 1
            
        # Update current position of the iterator
        iteratorIndex += 1
    frameCount = iteratorIndex - 1
    file.close()

# Read the handshake .csv file and parse that for specifics
with open(outputCSVFile_Handshakes, "r") as file:
    reader = csv.reader(file, delimiter=',')
    header = enumerate(reader)
    
    for row in reader:        
        # Count the number of handshakes
        if ("[SYN | ACK]" in row[10]):
            num3WayHandshakes += 1
            listOf3WayHandshakes.append(int(row[0]))

        if ("[FIN | ACK]" in row[10]):
            finAckCounter += 1
            if (finAckCounter >= 2):
                finAckCounter = 0
                numTerminationHandshakes += 1
                listOfTerminationHandshakes.append(int(row[0]))

    file.close()

# Write everything to a desired result file
file = open(outputResultsFile, "w")
file.write("===== Frame Capture Report =====\n\n")
file.write("Total number of frames: " + str(frameCount) + "\n")
file.write("Number of frames using the HTTP Protocol: " + str(httpFrameCount) + "\n")
file.write("Number of frames using the DNS Protocol: " + str(dnsFrameCount) + "\n")
file.write("Number of frames using the TCP Protocol: " + str(tcpFrameCount) + "\n")
file.write("Number of frames using the ARP Protocol: " + str(arpFrameCount) + "\n")
file.write("Number of frames using the UDP Protocol: " + str(udpFrameCount) + "\n")
file.write("Number of frames using the ICMP Protocol: " + str(icmpFrameCount) + "\n")
file.write("Number of times a 3-way handshake occurred: " + str(num3WayHandshakes) + "\n")
file.write("Number of times a termination handshake occurred: " + str(numTerminationHandshakes) + "\n\n")
file.write("The approximate frames where the 3-way handshakes occurred are:\n")
for synAckFrame in listOf3WayHandshakes:
    file.write(str(synAckFrame) + "\n")

file.write("\nThe approximate frames where the termination handshakes occurred are:\n")
for finAckFrame in listOfTerminationHandshakes:
    file.write(str(finAckFrame) + "\n")

file.close()

print("Results were successfully written to " + outputResultsFile)
print("")

# Display text from outputResultsFile to the console ; /E flag for the "more" command prevents the "Too many arguments in command line" error
printToConsoleCmd = "more /E " + outputResultsFile
os.system(printToConsoleCmd)
