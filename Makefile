main: main.o arp_request.o arp_request.h arp_spoofing.o arp_spoofing.h get_network_info.o get_network_info.h send_arp.o send_arp.h send_arp_for_all_user.o send_arp_for_all_user.h
	gcc -o main main.o arp_request.o arp_spoofing.o get_network_info.o send_arp.o send_arp_for_all_user.o -lpcap

main.o: main.c arp_request.h arp_spoofing.h get_network_info.h send_arp.h send_arp_for_all_user.h
	gcc -c main.c

arp_request.o: arp_request.c arp_request.h
	gcc -c arp_request.c

arp_spoofing.o: arp_spoofing.c arp_spoofing.h send_arp.h
	gcc -c arp_spoofing.c

get_network_info.o: get_network_info.c get_network_info.h
	gcc -c get_network_info.c

send_arp.o: send_arp.c send_arp.h
	gcc -c send_arp.c

send_arp_for_all_user.o: send_arp_for_all_user.c send_arp_for_all_user.h
	gcc -c send_arp_for_all_user.c

clean:
	rm *.o main  