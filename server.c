#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h> 

struct server {
    int sd;
    struct sockaddr_in addr;
};

struct dns_header {
    uint16_t id;
    uint8_t flags_1;
    uint8_t flags_2;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t bscount;
    uint16_t arcount;
};

struct dns_packet {
    struct dns_header header;
    uint8_t payload[512 - sizeof(struct dns_header)];
};

#define DH_FLAGS_QR(HEADER)((HEADER)->flags_1&1)
#define DH_FLAGS_OPCODE(HEADER)((HEADER)->flags_1>>1&Ob1111)
#define DH_FLAGS_AA(HEADER)((HEADER)->flags_1>>5&1)
#define DH_FLAGS_TC(HEADER)((HEADER)->flags_1>>6&1)
#define DH_FLAGS_RD(HEADER)((HEADER)->flags_1>>7)
#define DH_FLAGS_RA(HEADER)((HEADER)->flags_2>>7&1)
#define DH_FLAGS_Z(FLAGS)((FLAGS)->flags_2>>4&0b111)
#define DH_FLAGS_RCODE(FLAGS)((FLAGS)->flags_2&0b1111)

static int server_init(struct server * srv, int port)
{
    srv->sd = socket(PF_INET, SOCK_DGRAM, 0);
    if(srv->sd == -1)
        goto err_socket;
    
    srv->addr.sin_family = AF_INET;
    srv->addr.sin_port = htons(port);
    srv->addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(srv->sd, (struct sockaddr *)&srv->addr, sizeof(struct sockaddr_in)) < 0)
        goto err_bind;

    return 0;
    
err_socket:
err_bind:
    perror("server_init");
    return -1;
}

static int server_recv(struct server * srv) {

    struct dns_packet packet;
    socklen_t client_address_size;
    struct sockaddr_in client;
    ssize_t size;
    
    size = recvfrom(
        srv->sd, &packet, sizeof(struct dns_packet), 0, 
        (struct sockaddr *) &client, &client_address_size
    );
    if(size < 0)
    {
       perror("recvfrom()");
       exit(4);
    }
    
    puts("REV");
    printf("    client_address_size: %d\n", client_address_size);
    printf("    size: %ld\n", size);
    
    if(size > sizeof(struct dns_header)) {

        packet.header.id = ntohs(packet.header.id);
        //packet.header.flags = ntohs(packet.header.flags);
        packet.header.qdcount = ntohs(packet.header.qdcount);
        packet.header.ancount = ntohs(packet.header.ancount);
        packet.header.bscount = ntohs(packet.header.bscount);
        packet.header.arcount = ntohs(packet.header.arcount);
    
        printf("dns_header:\n");
        printf("    id: %#x\n", packet.header.id);
        printf("    flags: %#x\n", packet.header.flags_1);
        printf("        is a query: %d\n", DH_FLAGS_QR(&packet.header));
        printf("    flags: %#x\n", packet.header.flags_2);
        printf("    qdcount: %u\n", packet.header.qdcount);
        printf("    ancount: %u\n", packet.header.ancount);
        printf("    bscount: %u\n", packet.header.bscount);
        printf("    arcount: %u\n", packet.header.arcount);
    }
    
    return 0;
}

int main(void)
{
    struct server srv;

    if(server_init(&srv, 53) != 0)
        exit(-1);
    
    puts("RECV");
    
    server_recv(&srv);
}
