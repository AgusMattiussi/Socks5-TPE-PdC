/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de la línea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en este hilo.
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
#include "args.h"

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>

//TODO: #include "socks5.h"
#include "src/selector/selector.h"
//TODO: #include "socks5nio.h"

void socksv5_passive_accept(struct selector_key * key);

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int
main(const int argc, const char **argv) {
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    close(STDIN_FILENO);

    struct socks5args args;
    parse_args(argc, argv, &args);

    int returnCode = start_server(args.socks_addr, args.sockport);

    return returnCode;
    /*
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

    fprintf(stdout, "Listening on TCP port %d\n", port);

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
    printf("ANTES\n");
    struct banana * unaBanana = (struct banana *) key->data;
    printf("FD de la banana: %d\n", unaBanana->fd);
    send(unaBanana->fd, "Estas leyendo", strlen("Estas leyendo"), 0);
    printf("DESPUES\n");
}

void newFdWrite(struct selector_key *key){
    printf("Escribiendo Pa\n");

    struct banana * unaBanana = (struct banana *) key->data;
    printf("FD de la banana: %d\n", unaBanana->fd);
    send(unaBanana->fd, "Estas Escribiendo", strlen("Estas Escribiendo"), 0);
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

    printf("FD Original: %d\n", new_fd);

    if( send(new_fd, "Bienvenido!!", strlen("Bienvenido!!"), 0) != strlen("Bienvenido!!") ) {
        printf("ERROR EN send \n");
    }

    if( send(new_fd, "Bienvenido2!!", strlen("Bienvenido2!!"), 0) != strlen("Bienvenido2!!") ) {
        printf("ERROR EN send \n");
    }

    if( send(new_fd, "Bienvenido3!!", strlen("Bienvenido3!!"), 0) != strlen("Bienvenido3!!") ) {
        printf("ERROR EN send \n");
    }

    struct banana * unaBanana = malloc(sizeof(struct banana));
    unaBanana->fd = new_fd;

    fd_handler new_fd_handler = {&newFdRead, &newFdWrite, &newFdBlock, &newFdClose};


    if(selector_register(key->s, new_fd, &new_fd_handler, OP_WRITE, unaBanana) != 0){
        printf("Error en el register \n");
    }*/

}