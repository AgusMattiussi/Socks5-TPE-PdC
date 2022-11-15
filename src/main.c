/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de lÃ­nea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarÃ¡n en Ã©ste hilo.
 *
 * Se descargarÃ¡ en otro hilos las operaciones bloqueantes (resoluciÃ³n de
 * DNS utilizando getaddrinfo), pero toda esa complejidad estÃ¡ oculta en
 * el selector.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#include <stdbool.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include "src/socks5/socks5.h"
#include "include/selector.h"
#include "include/buffer.h"
#include "src/include/args.h"
//TODO: #include "socks5nio.h"

#define DEST_PORT 9090
#define MAX_ADDR_BUFFER 128

struct banana {
    int fd;
};


void socksv5_passive_accept(struct selector_key * key);
void serverRead(struct selector_key *key);
void serverWrite(struct selector_key *key);
void clientRead(struct selector_key *key);
void clientWrite(struct selector_key *key);

static bool done = false;
static buffer clientBuffer;
static buffer serverBuffer;
static uint8_t clientBufferData[1024];
static uint8_t serverBufferData[1024];

int clientFd = -1;
int serverFd = -1;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int
main(const int argc, const char **argv) {
    unsigned port = 1080;
    /* char * destPort = "9090";
    char * destIp = "localhost"; */

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    close(STDIN_FILENO);

    struct socks5args args;
    parse_args(argc, argv, &args);

    int returnCode = start_server(args.socks_addr, args.socks_port);

    return returnCode;

    /* if(argc == 1) {
        // utilizamos el default
    } else if(argc >= 2 || argc<=4) {
        char *end     = 0;
        const long sl = strtol(argv[1], &end, 10);

        if (end == argv[1]|| '\0' != *end 
           || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
           || sl < 0 || sl > USHRT_MAX) {
            fprintf(stderr, "port should be an integer: %s\n", argv[1]);
            return 1;
        }
        port = sl;

        if(argc >= 3)
            destIp = argv[2];

        if(argc >= 4)
            destPort = argv[3];

    } else {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    } 

    // no tenemos nada que leer de stdin
    close(0);

    const char       *err_msg = NULL;
    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;

    buffer_init(&clientBuffer, 1024, clientBufferData);
    buffer_init(&serverBuffer, 1024, serverBufferData);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);

    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(server < 0) {
        err_msg = "unable to create socket";
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %d (FD:%d)\n", port, server);

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    if(bind(server, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        err_msg = "unable to bind socket";
        goto finally;
    }

    if (listen(server, 20) < 0) {
        err_msg = "unable to listen";
        goto finally;
    }

    // registrar sigterm es Ãºtil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    if(selector_fd_set_nio(server) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }
    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };
    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if(selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }
    const struct fd_handler socksv5 = {
        .handle_read       = socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    ss = selector_register(selector, server, &socksv5,
                                              OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    } */
/* 
    // =================== Server para el proxy TCP ===================
    printf("CREANDO SOCKET PARA EL PROXY TCP\n");
	struct addrinfo addrCriteria;                   // Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;             // v4 or v6 is OK
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only streaming sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

	// Get address(es)
	struct addrinfo *servAddr; // Holder for returned list of server addrs
	int rtnVal = getaddrinfo(destIp, destPort, &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		return -1;
	}

	for (struct addrinfo *addr = servAddr; addr != NULL && serverFd == -1; addr = addr->ai_next) {
		// Create a reliable, stream socket using TCP
		serverFd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        printf("serverFd = %d\n", serverFd);
		if (serverFd >= 0) {
			errno = 0;
			// Establish the connection to the server
			if ( connect(serverFd, addr->ai_addr, addr->ai_addrlen) != 0) {
				close(serverFd); 	// Socket connection failed; try next address
				serverFd = -1;
			}
		} else {
			printf("Can't create client socket"); 
		}
	}
    selector_fd_set_nio(serverFd);

    struct banana * unaBanana = malloc(sizeof(struct banana));
    unaBanana->fd = serverFd;
    fd_handler serverFdHandler = {&serverRead, &serverWrite, NULL, NULL};
    selector_register(selector, serverFd, &serverFdHandler, OP_READ, unaBanana);

    send(serverFd, "booenas\n", strlen("booenas\n"), 0);
    printf("\nLISTO\n\n");

    // ==============================================================================================
 */
}


void clientRead(struct selector_key *key){
    printf("clientRead\n");
    struct banana * unaBanana = (struct banana *) key->data;

    if(!buffer_can_write(&clientBuffer))
        return;
    
    size_t nByte = 0;

    uint8_t * buf = buffer_write_ptr(&clientBuffer, &nByte);
    int bytes = recv(unaBanana->fd, buf, nByte, 0);

    if(bytes < 0){
        printf("Error en recv\n");
        return;
    }
    if(bytes == 0) {
        printf("Cerrada conexion cliente\n");
        return;
    }
        
    buffer_write_adv(&clientBuffer, bytes);
    selector_set_interest(key->s, serverFd, OP_WRITE);
    printf("LEIDO PAAAAAA\n");
}

void clientWrite(struct selector_key *key){
    printf("clientWrite\n");
    struct banana * unaBanana = (struct banana *) key->data;

    if(!buffer_can_read(&serverBuffer))
        return;
    size_t nByte = 0;
    uint8_t * buf = buffer_read_ptr(&serverBuffer, &nByte);

    int sent = send(unaBanana->fd, buf, nByte, 0);
    if(sent < 0){
        printf("Error en send\n");
        return;
    }
    if(sent == 0){
        printf("Cerrada conexion servidor\n");
        return;    
    }
    buffer_read_adv(&serverBuffer, sent);
    if(!buffer_can_read(&serverBuffer))
        selector_set_interest(key->s, clientFd, OP_READ);
}

void serverRead(struct selector_key *key){
    printf("serverRead\n");
    struct banana * unaBanana = (struct banana *) key->data;

    if(!buffer_can_write(&serverBuffer))
        return;
    
    size_t nByte = 0;

    uint8_t * buf = buffer_write_ptr(&serverBuffer, &nByte);
    int bytes = recv(unaBanana->fd, buf, nByte, 0);

    if(bytes < 0){
        printf("Error en recv\n");
        return;
    }
    if(bytes == 0) {
        printf("Cerrada conexion servidor\n");
        return;
    }
        
    buffer_write_adv(&serverBuffer, bytes);
    selector_set_interest(key->s, clientFd, OP_WRITE);
    printf("LEIDO PAAAAAA\n");
}

void serverWrite(struct selector_key *key){
    printf("serverWrite\n");
    struct banana * unaBanana = (struct banana *) key->data;

    if(!buffer_can_read(&clientBuffer))
        return;

    size_t nByte = 0;
    uint8_t * buf = buffer_read_ptr(&clientBuffer, &nByte);
    int sent = send(unaBanana->fd, buf, nByte, 0);
    if(sent < 0){
        printf("Error en send\n");
        return;
    }
    if(sent == 0){
        printf("Cerrada conexion servidor\n");
        return;    
    }
    buffer_read_adv(&clientBuffer, sent);
    if(!buffer_can_read(&clientBuffer))
        selector_set_interest(key->s, serverFd, OP_READ);
    
}

void newFdClose(struct selector_key *key){
    selector_unregister_fd(key->s, ((struct banana *)key)->fd);
    printf("Cerrando Pa\n");
}

void newFdBlock(struct selector_key *key){
    printf("Bloqueando Pa\n");
}

/* void socksv5_passive_accept(struct selector_key * key) {
    int master_fd = key->fd;
    
    if(clientFd != -1)
        return;

    if((clientFd = accept(master_fd, NULL, NULL)) < 0){
        printf("ERROR EN accept \n");
    }

    if( send(clientFd, "Bienvenido!!\n", strlen("Bienvenido!!\n"), 0) != strlen("Bienvenido!!\n") ) {
        printf("ERROR EN send \n");
    }

    struct banana * unaBanana = malloc(sizeof(struct banana));
    unaBanana->fd = clientFd;
    fd_handler clientFdHandler = {&clientRead, &clientWrite, &newFdBlock, &newFdClose};


    if(selector_register(key->s, clientFd, &clientFdHandler, OP_READ, unaBanana) != 0){
        printf("Error en el register \n");
    }

} */