packetspammer: wifinjector.c
	gcc -Wall -Wextra radiotap.c wifinjector.c -o wifinjector -lpcap -lpthread -lboost_system -g

clean:
	rm -f wifinjector *~