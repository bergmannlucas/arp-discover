/**
* ARP Spoofing
* David Caina e Lucas Bergmann
**/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h> 
#include <pthread.h>


typedef struct _arp_hdr arp_hdr;
struct _arp_hdr { 
   
   // ---- DLC Header ---- //
   unsigned char broadcast_mac[6];  // Broadcast FF:FF:FF:FF:FF:FF	
   unsigned char sender_mac[6];     // MAC origem
   unsigned short eth_type;         // 0x0806(ARP)

   // ---- ARP frame ---- //
   unsigned short hw_type;          // Hardware type = 1 para ethernet
   unsigned short proto_type;       // Protocol type = Internet Protocol packet ETH_P_IP
   unsigned char hw_size;           // Hardware size = 6 bytes
   unsigned char proto_size;        // Protocol size = 4 bytes
   unsigned short opcode;           // 1 para request

   unsigned char sender_mac_address[6];      // MAC origem
   unsigned char sender_protocol_address[4]; // IP origem
   unsigned char receiver_mac_address[6];      // MAC destino
   unsigned char receiver_protocol_address[4]; // IP destino
   
   unsigned char padding[18]; // 18 bytes de padding
};

char ifname[IFNAMSIZ];

int main(int argc, char *argv[]) {
	if (argc != 4) {
		printf("Uso: %s <interface> <ip alvo> <ip roteador> \n", argv[0]);
		return 1;
	}
	
	strcpy(ifname, argv[1]);
}
