all: pcap-test

pcap-test: pcap-test.c
	gcc -o pcap-test pcap-test.c -l pcap

clean:
	rm -rf pcap-test