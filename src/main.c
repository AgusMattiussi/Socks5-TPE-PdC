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
//TODO: #include "socks5.h"
#include "include/selector.h"
//TODO: #include "socks5nio.h"

#define DEST_PORT 9090
#define MAX_ADDR_BUFFER 128

void socksv5_passive_accept(struct selector_key * key);

static bool done = false;
int destFd = 0;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int
main(const int argc, const char **argv) {
    unsigned port = 1080;


    if(argc == 1) {
        // utilizamos el default
    } else if(argc == 2) {
        char *end     = 0;
        const long sl = strtol(argv[1], &end, 10);

        if (end == argv[1]|| '\0' != *end 
           || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
           || sl < 0 || sl > USHRT_MAX) {
            fprintf(stderr, "port should be an integer: %s\n", argv[1]);
            return 1;
        }
        port = sl;
    } else {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    // no tenemos nada que leer de stdin
    close(0);

    const char       *err_msg = NULL;
    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;

    

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
    }

    // =================== Server para el proxy TCP ===================
    printf("CREANDO SOCKET PARA EL PROXY TCP\n");
	struct addrinfo addrCriteria;                   // Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;             // v4 or v6 is OK
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only streaming sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

	// Get address(es)
	struct addrinfo *servAddr; // Holder for returned list of server addrs
	int rtnVal = getaddrinfo("localhost", "9090", &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		return -1;
	}

	destFd = -1;
	for (struct addrinfo *addr = servAddr; addr != NULL && destFd == -1; addr = addr->ai_next) {
		// Create a reliable, stream socket using TCP
		destFd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        printf("destfd = %d\n", destFd);
		if (destFd >= 0) {
			errno = 0;
			// Establish the connection to the server
			if ( connect(destFd, addr->ai_addr, addr->ai_addrlen) != 0) {
				close(destFd); 	// Socket connection failed; try next address
				destFd = -1;
			}
		} else {
			printf("Can't create client socket"); 
		}
	}
    selector_fd_set_nio(destFd);

    send(destFd, "booenas\n", strlen("booenas\n"), 0);
    printf("\nLISTO\n\n");

    // ==============================================================================================

    for(;!done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    if(err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;
finally:
    if(ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "": err_msg,
                                  ss == SELECTOR_IO
                                      ? strerror(errno)
                                      : selector_error(ss));
        ret = 2;
    } else if(err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    //TODO: socksv5_pool_destroy();

    if(server >= 0) {
        close(server);
    }
    return ret;
}

struct banana {
    int fd;
};

void newFdRead(struct selector_key *key){
    printf("Leyendo Pa\n");
    struct banana * unaBanana = (struct banana *) key->data;
    char buffer[1024];


    int bytes = recv(unaBanana->fd, buffer, 1023, 0);
    if(bytes < 0)
        printf("No recibi bien\n");
    buffer[bytes] = '\0';

    printf("RECIBI: %s, lo voy a mandar a %d\n", buffer, destFd);

    int sent = send(destFd, buffer, strlen(buffer), 0);
    if(sent < 0)
        printf("No escribi bien\n");
    if(sent == 0)
        printf("Manda algo salame\n");

    printf("ENVIE: %s\n", buffer);
    printf("LEIDO PAAAAAA\n");
}

void newFdWrite(struct selector_key *key){
    printf("Escribiendo Pa\n");
}

void newFdClose(struct selector_key *key){
    selector_unregister_fd(key->s, ((struct banana *)key)->fd);
    printf("Cerrando Pa\n");
}

void newFdBlock(struct selector_key *key){
    printf("Bloqueando Pa\n");
}

void socksv5_passive_accept(struct selector_key * key) {
    int master_fd = key->fd;
    int new_fd;

    if((new_fd = accept(master_fd, NULL, NULL)) < 0){
        printf("ERROR EN accept \n");
    }

    if( send(new_fd, "Bienvenido!!", strlen("Bienvenido!!"), 0) != strlen("Bienvenido!!") ) {
        printf("ERROR EN send \n");
    }

    struct banana * unaBanana = malloc(sizeof(struct banana));
    unaBanana->fd = new_fd;
    fd_handler new_fd_handler = {&newFdRead, &newFdWrite, &newFdBlock, &newFdClose};


    if(selector_register(key->s, new_fd, &new_fd_handler, OP_READ, unaBanana) != 0){
        printf("Error en el register \n");
    }

}