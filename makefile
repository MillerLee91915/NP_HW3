all: sniffer.c
	gcc -g -o sniffer sniffer.c -lpcap

clean: 
	$(RM) sniffer