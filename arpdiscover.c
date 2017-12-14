/**
* ARP Discover
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

#define ETHERTYPE 0x0806
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500
#define ARP_HDRLEN 28
#define ETH_HDRLEN 14


pthread_mutex_t mutex1, mutex2;
struct in_addr *ip;	// struct para lidar com ip's
char ifname[IFNAMSIZ];
char str[INET_ADDRSTRLEN];

void * arpreply() {

	//pthread_mutex_lock(&mutex2);
	//int cont;
	int fd, n, i;
	arp_hdr arphdr;
	struct sockaddr dispositivo;
	unsigned char sender_mac_address[6];
	unsigned char sender_protocol_address[4];

	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE))) < 0) {
		perror("Erro ao criar socket");
		exit(1);
	}
	
	i = 1;
	do {
		// Limpando para cada reply  
		memset(&dispositivo, 0x00, sizeof(dispositivo));
		memset(&arphdr, 0x00, sizeof(arphdr));
		n = sizeof(dispositivo);

		// Recebe pacote
		if (recvfrom(fd, &arphdr, sizeof(arphdr), 0, (struct sockaddr*)&dispositivo, &n) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}

	
				
		if ((ntohs(arphdr.opcode) == ARPOP_REPLY)) {
				printf("Encontrado HOST de numero: %d\n", i);
				i++;
				
				memcpy(sender_mac_address, &arphdr.sender_mac_address, 6);
				memcpy(sender_protocol_address, &arphdr.sender_protocol_address, 4);
				printf("IP ADDRESS: %u.%u.%u.%u",
					   sender_protocol_address[0],
					   sender_protocol_address[1],
					   sender_protocol_address[2],
					   sender_protocol_address[3]);

				printf("    MAC ADDRESS: %02x:%02x:%02x:%02x:%02x:%02x\n",
					   sender_mac_address[0],
					   sender_mac_address[1],
					   sender_mac_address[2],
					   sender_mac_address[3],
					   sender_mac_address[4],
					   sender_mac_address[5]);
		} 
	} while(1);

	close(fd);

	pthread_exit(NULL);
	//pthread_mutex_unlock(&mutex2);
}

void * arprequest() {
	int fd, fd2, i;
	struct ifreq ifr;
	//struct ifreq if_mac;
	//struct ifreq if_idx;
	arp_hdr arphdr; 
	struct sockaddr dispositivo;


	//pthread_mutex_lock(&mutex1);
	printf("\n\n####################### ARP DISCOVER #######################\n");
	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("Erro ao criar socket");
		exit(1);
	}


        /* Obtem o endereco MAC da interface local */
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("Erro ao obter MAC de origem!");
		exit(1);
	}

	/* Obtem o endereco IP da interface local */
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		perror("SIOCGIFADDR");
		exit(1);
	}

	/* Montando o ARP REQUEST packet */
	memset(&arphdr.broadcast_mac, 0xFF, 6);
	memcpy(&arphdr.sender_mac, &ifr.ifr_hwaddr.sa_data, 6);
	arphdr.eth_type = htons(ETHERTYPE);
	arphdr.hw_type = htons (1); 
	arphdr.proto_type = htons (ETH_P_IP); 
	arphdr.hw_size = 6; 
	arphdr.proto_size = 4; 
	arphdr.opcode = htons (ARPOP_REQUEST); 
	memcpy(&arphdr.sender_mac_address, &ifr.ifr_hwaddr.sa_data, 6);
	memcpy(&arphdr.sender_protocol_address, &ifr.ifr_hwaddr.sa_data[2], 4);
	memset(&arphdr.receiver_mac_address, 0x00, 6);
	memcpy(&arphdr.receiver_protocol_address, &arphdr.sender_protocol_address, 3);
	memset(&arphdr.padding, 0, 18);
	

	printf("Enviando pacotes ARP...\n\n\n");

	/* BROADCAST PROCURANDO PCS */
	i = 1;
	while (i < 255) {
		arphdr.receiver_protocol_address[3] = i;
		/* Cria um descritor de socket do tipo IPv4 */
		if ((fd2 = socket(AF_INET, SOCK_PACKET, htons(ETHERTYPE))) == -1) {
			perror("Erro ao criar socket");
			exit(1);
		}

		memset(&dispositivo, 0x00, sizeof(dispositivo));
		strcpy(dispositivo.sa_data, ifname);
		
		if (sendto(fd2, &arphdr, sizeof(arphdr), 0, (struct sockaddr *) &dispositivo, sizeof (dispositivo)) < 0) {
           		perror("send");
           		close(fd2);
           		exit(1);
        	}    
		
		i++;
		close(fd2);
		//tam_frame = tam_frame_backup;
		//close(fd);

	}

	pthread_exit(NULL);
	//pthread_mutex_unlock(&mutex1);
	//return 0;
}

int main(int argc, char *argv[]) {
	pthread_t thread1, thread2;
	//pthread_mutex_init(&mutex1, NULL);
	//pthread_mutex_init(&mutex2, NULL);

	//pthread_mutex_lock(&mutex2);

	if (argc != 2) {
		printf("Uso: %s <interface>\n", argv[0]);
		return 1;
	}

	strcpy(ifname, argv[1]);
	
	if(pthread_create(&thread1, NULL, arprequest, NULL) != 0 ) {
		fprintf(stderr, "Erro ao criar thread de request\n");
		return 1;
	}

	if(pthread_create(&thread2, NULL, arpreply, NULL) != 0 ) {
		fprintf(stderr, "Erro ao criar thread de reply\n");
		return 1;
	}

	sleep(5); //espera ocupada
	printf("\n\n");

	return 0;
}
