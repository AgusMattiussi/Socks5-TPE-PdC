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
#include "include/stm.h"
#include "logger/logger.h"
#include "include/metrics.h"

#define DEST_PORT 9090
#define MAX_ADDR_BUFFER 128
#define INITIAL_N 20

//void socksv5_passive_accept(struct selector_key * key);
static bool done = false;

static void
sigterm_handler(const int signal) {
    LogDebug("Exiting...");
    done = true;
    cleanup();
    exit(0);
}

static void
start_selector(){
    // Initialization of selector struct
    struct timespec select_timeout = {0};
    select_timeout.tv_sec = 100;
    struct selector_init select_init_struct = {SIGCHLD, select_timeout};

    // Configure the selector
    int selector_init_retvalue = -1;
    selector_init_retvalue = selector_init(&select_init_struct);
    if(selector_init_retvalue != SELECTOR_SUCCESS){
        LogError("Selector initialization failed: %s",
        selector_error(selector_init_retvalue));
    }  

    // Initialize the selector
    fd_selector selector = selector_new(INITIAL_N);
    set_selector(&selector);
    if(selector == NULL){
        LogError("Selector creation failed");
    }
}

int
main(const int argc, char ** argv) {
    
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    struct socks5args args;
    parse_args(argc, argv, &args);
    close(STDIN_FILENO);
    start_metrics();
    start_selector();   

    start_server(args.socks_addr, args.socks_port, args.mng_addr, args.mng_port);

    return 0;
}