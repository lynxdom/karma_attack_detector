# File Name	: Makefile
# Author	: Sean Alexander
# Creation      : 4/15/2017
#
# Descrition  :
# Makefile to build the Karma Detect Project
#

# use a variable to call the compiler
CC = g++

# Include the c++11 std and Wall turns on 
# the warnings.
CFLAGS = -std=c++11 -Wall -lpcap -lpthread

# top level 
DEPENDS = HardwareAddress.o probe.o sniffer.o

all: KarmaDetection

KarmaDetection: $(DEPENDS) KarmaDetection.cpp
		$(CC) $(CFLAGS) $(DEPENDS) KarmaDetection.cpp -o KarmaDetection
		
HardwareAddress.o: HardwareAddress.cpp HardwareAddress.h
	$(CC) $(CFLAGS) -c HardwareAddress.cpp
	
probe.o: probe.cpp probe.h KarmaType.h
	$(CC) $(CFLAGS) -c probe.cpp
	
sniffer.o: sniffer.cpp sniffer.h KarmaType.h
	$(CC) $(CFLAGS) -c sniffer.cpp
	
clean:
	rm -rf *o KarmaDetection