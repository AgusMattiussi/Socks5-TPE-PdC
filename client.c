
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include "proto.h"

#define D_ADDR "127.0.0.1"
#define D_PORT "9090"

int proto_connect(char * addr, char * port);
void client_parse_args(int argc, char ** argv, struct proto * args);

static void
usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTION]...\n"
        "\n"
        /*"   -h               Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
        "   -L <conf  addr>  Dirección donde servirá el servicio de management.\n"
        "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
        "   -P <conf port>   Puerto entrante conexiones configuracion\n"
        "   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
        "   -v               Imprime información sobre la versión versión y termina.\n"
        "\n"
        "   --doh-ip    <ip>    \n"
        "   --doh-port  <port>  XXX\n"
        "   --doh-host  <host>  XXX\n"
        "   --doh-path  <host>  XXX\n"
        "   --doh-query <host>  XXX\n"
        */
        "acá imprimimos el help"
        "\n",
        progname);
    exit(1);
}


int main(int argc, char ** argv) {

    struct proto args;

    char * addr = D_ADDR;
    char * port = D_PORT;

    client_parse_args(argc, argv, &args);

    if(args.addr != NULL) 
        addr = args.addr;

    if(args.port != NULL) 
        port = args.port;   

    int c = proto_connect(addr, port);

    return 0;
	
    
}

void client_parse_args(int argc, char ** argv, struct proto * args) {

    memset(args, 0, sizeof(*args));

    int c;
    while ((c = getopt(argc, argv, "h::p:l")) != -1) {
        switch (c) {
            case 'h':
                usage("nuestroprotocolo");
                break;
            case 'p':
                args->port = optarg;
                break;
            case 'l':
                args->addr = optarg;
                break;
            /*case '?':
                admin_usage();
                printf("Invalid Arguments");
                exit(1);*/

        }
    }

}


int proto_connect(char * addr, char * port) {

    struct addrinfo addrCriteria;                  
	memset(&addrCriteria, 0, sizeof(addrCriteria)); 
	addrCriteria.ai_family = AF_UNSPEC;            
	addrCriteria.ai_socktype = SOCK_STREAM;        
	struct addrinfo *servAddr; 


    int status;
    if ((status = getaddrinfo(addr, port, &addrCriteria, &servAddr)) != 0) {
        return -1;
    }

    for (struct addrinfo * dir = servAddr; dir != NULL; dir = dir->ai_next) {
        
        int proxy_socket = socket(dir->ai_family, dir->ai_socktype, dir->ai_protocol);
        
        if (proxy_socket == -1)
            continue;

        if (connect(proxy_socket, dir->ai_addr, dir->ai_addrlen) != 0)
            continue;
 
        send(proxy_socket, "buenardas!\n", strlen("buenardas!\n"), 0);
        break;
    }
}