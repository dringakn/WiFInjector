packetspammer: wifinjector.c
	gcc -Wall wifinjector.c -o wifinjector -lpcap

clean:
	rm -f wifinjector *~