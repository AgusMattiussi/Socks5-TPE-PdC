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
#include "socks5/socks5.h"
#include "include/selector.h"
#include "include/buffer.h"
#include "include/args.h"
#include "include/server.h"

//TODO: #include "socks5nio.h"

#define DEST_PORT 9090
#define MAX_ADDR_BUFFER 128

/* struct fdStruct {
    int fd;
}; */


void socksv5_passive_accept(struct selector_key * key);
/* void serverRead(struct selector_key *key);
void serverWrite(struct selector_key *key);
void clientRead(struct selector_key *key);
void clientWrite(struct selector_key *key);
void newFdClose(struct selector_key *key);
void newFdBlock(struct selector_key *key); */

static bool done = false;
/* static buffer clientBuffer;
static buffer serverBuffer;
static uint8_t clientBufferData[1024];
static uint8_t serverBufferData[1024]; */

/* int clientFd = -1;
int serverFd = -1;
int clientInterest = OP_NOOP;
int serverInterest = OP_NOOP; */

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int
main(const int argc, char **argv) {
    //unsigned port = 1080;
    /* char * destPort = "9090";
    char * destIp = "localhost"; */

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    close(STDIN_FILENO);

    struct socks5args args;
    parse_args(argc, argv, &args);

    int returnCode = start_server(args.socks_addr, args.socks_port);

    return returnCode;
}