#include "include/server.h"
#include "logger/logger.h"
#include "include/metrics.h"

#define MAX_QUEUE 50
static fd_selector selector;

static void passive_socks_socket_handler(struct selector_key * key);
static void passive_cp_socket_handler(struct selector_key * key) ;

const struct fd_handler passive_socket_fd_handler = {
    .handle_read = passive_socks_socket_handler, 
    .handle_write = 0, 
    .handle_block = 0, 
    .handle_close = 0
};

const struct fd_handler passive_socket_fd_mng_handler = {passive_cp_socket_handler, 0, 0, 0};


const struct fd_handler conn_actions_handler = { 
    .handle_read = socks_conn_read,
    .handle_write = socks_conn_write,
    .handle_block = socks_conn_block,
    .handle_close = socks_conn_close
};


const struct fd_handler * get_conn_actions_handler() {
    return &conn_actions_handler;
}


void 
close_socks_conn(socks_conn_model * socks) {

    int client_socket = socks->cli_conn->socket;
    int server_socket = socks->src_conn->socket;

    if (server_socket != -1) {
        selector_unregister_fd(selector, server_socket, false);
        close(server_socket);
    }
    if (client_socket != -1) {
        remove_current_socks_connection();    
        selector_unregister_fd(selector, client_socket, false);
        close(client_socket);
    }
    if (socks->resolved_addr != NULL) {
        freeaddrinfo(socks->resolved_addr);
    }

    free_curr_user();

    buffer_reset(&socks->buffers->read_buff);
    buffer_reset(&socks->buffers->write_buff);

    free(socks->buffers->aux_read_buff);
    free(socks->buffers->aux_write_buff);
    
    free(socks->buffers);

    free(socks->parsers->auth_parser);
    free(socks->parsers->connect_parser);
    free(socks->parsers->req_parser);
    free(socks->parsers);

    free(socks->pop3_parser);

    free(socks->cli_conn);
    free(socks->src_conn);

    free(socks);
}

const fd_handler cpFdHandler = {
    .handle_read = cpReadHandler,
    .handle_write = cpWriteHandler,
    .handle_block = NULL,
    .handle_close = cpCloseHandler
};


static void passive_cp_socket_handler(struct selector_key * key) {
    LogInfo(" En passive_cp_socket_handler\n");
    controlProtConn * new;
    
    /* Aceptamos la conexion entrante */
    int clientFd = accept(key->fd, NULL, NULL);
    if(clientFd < 0){
        LogError(" ERROR en passive_cp_socket_handler (accept)\n");
        return;
    }

    /* Hacemos el socket no bloqueante */
    if(selector_fd_set_nio(clientFd) == -1){
        LogError(" ERROR en passive_cp_socket_handler (selector_fd_set_nio)\n");
        close(clientFd);
        return;
    }

    /* Inicializamos la estructura con los datos de esta conexion */
    // TODO: Considerar aniadirlo a una lista para liberar todo al?
    new = newControlProtConn(clientFd, key->s);
    if(new == NULL){
        LogError(" ERROR en passive_cp_socket_handler (newControlProtConn)\n");
        close(clientFd);
        return;
    }

    if(selector_register(key->s, new->fd, /*TODO: Completar handlers*/ &cpFdHandler, new->interests, new) != 0){
        LogError(" ERROR en passive_cp_socket_handler (selector_register)\n");
        freeControlProtConn(new, key->s); // Esto incluye el cerrado de clientFd
        return;
    }
    add_mgmt_connection(); // Metrics
    LogInfo(" Socket pasivo creado exitosamente \n");
}

static void 
passive_socks_socket_handler(struct selector_key * key){
    //TODO: Check if enough fds are available

    socks_conn_model * socks = new_socks_conn();
    
    //After setting up the configuration, we accept the socks
    socks->cli_conn->addr_len = sizeof(socks->cli_conn->addr);
    socks->cli_conn->socket = accept(key->fd, (struct sockaddr *)&socks->cli_conn->addr,
    &socks->cli_conn->addr_len);
    if(socks->cli_conn->socket == -1){
        LogError("Error in accept call");
        close_socks_conn(socks);
        return;
    }
 
    int sel_ret = selector_fd_set_nio(socks->cli_conn->socket);
    if(sel_ret == -1){
        LogError("Error in selector_fd_set_nio call");
        close_socks_conn(socks);
        return;
    }
    
    selector_status sel_register_ret = selector_register(selector, socks->cli_conn->socket,
        &conn_actions_handler, OP_READ, socks);
    if(sel_register_ret != SELECTOR_SUCCESS){
        LogError("Error in selector_fregister call: %s",
        selector_error(sel_register_ret));
        close_socks_conn(socks);
        return;
    }
    add_socks_connection(); // Metrics
}


static int start_socket(char * ip_addr, char * port,
                        const struct fd_handler * handler, int ai_family){
    int ret_fd;
    struct addrinfo hints; //Naming corresponding to fields in 'man getaddrinfo'
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = ai_family;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
    struct addrinfo * res = NULL;
    int error = 0;

    int addr_info;
    addr_info = getaddrinfo(ip_addr, port, &hints, &res);
    if(addr_info){
        LogError("Error en getaddrinfo. %s", gai_strerror(addr_info));
        error = -1;
        goto finally;
    }

    ret_fd = socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if(ret_fd == -1){
        LogError("Error creating socket");
        perror("socket");
        error=-1;
        goto finally;    
    }

    //Reuse address
    int ret_setsockopt = -1;
    ret_setsockopt = setsockopt(ret_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    if(ret_setsockopt == -1){
        LogError("Error setstockopt");
        perror("socket");
        error=-1;
        goto finally;    
    }

    //Set for IPv6 if necessary
    if(ai_family == AF_INET6){
        int ret_setsockopt_ipv6;
        ret_setsockopt_ipv6 = setsockopt(ret_fd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int));
        if(ret_setsockopt_ipv6 == -1){
            LogError("Error setstockopt");
            perror("Socket: ");
            error = -1;
            goto finally;
        }
    }

    int ret_bind = bind(ret_fd, res->ai_addr, res->ai_addrlen);
    if(ret_bind < 0){
        LogError("Error in bind call");
        perror("Bind: ");
        goto finally;
        }

    int ret_listen = listen(ret_fd, MAX_QUEUE);
    if(ret_listen < 0){ 
        LogError("Error in listen call");
        perror("Listen: ");
        error=-1;
        goto finally; 
    }

    int ret_register = selector_register(selector, ret_fd, handler, OP_READ, NULL);
    if(ret_register != SELECTOR_SUCCESS){
        LogError("Error selector_register");
        error=-1;
        goto finally;
    }
finally:
    if(error == -1 && ret_fd != -1){ close(ret_fd); ret_fd = -1;}
    freeaddrinfo(res);
    return ret_fd;
}


void start_server(char * socks_addr, char * socks_port, char * mng_addr, char * mng_port){
    int fd_socks_ipv4 = -1, fd_socks_ipv6 = -1, fd_mng_ipv4 = -1, fd_mng_ipv6 = -1;

    fd_socks_ipv4 = start_socket(socks_addr, socks_port, &passive_socket_fd_handler, AF_UNSPEC);
    if(fd_socks_ipv4 == -1){ 
        LogError("Failed to start IPv4 socket");
        goto finally; 
    }
    else if(socks_addr == NULL){
        fd_socks_ipv6 = start_socket(NULL, socks_port, &passive_socket_fd_handler, AF_INET6);
        if(fd_socks_ipv6 == -1){
            LogError("Failed to start IPv6 socket");
            goto finally; 
        }
    }
    fd_mng_ipv4 = start_socket(mng_addr, mng_port, &passive_socket_fd_mng_handler, AF_UNSPEC);
    if(fd_mng_ipv4 == -1){ 
        LogError("Falle en start_socket ipv4, linea 150 de start_server\n");
        goto finally; }
    else if(mng_addr == NULL){
        fd_mng_ipv6 = start_socket(NULL, mng_port, &passive_socket_fd_mng_handler, AF_INET6);
        if(fd_mng_ipv6 == -1){
            LogError("Falle en start socket ipv6, linea 155 de start_server\n");
            goto finally; 
        }
    }

    while(1){
        int selector_ret_value = selector_select(selector);
        if(selector_ret_value != SELECTOR_SUCCESS){goto finally;}
    }

finally:
    if(fd_socks_ipv4 != -1){close(fd_socks_ipv4);}
    if(fd_socks_ipv6 != -1){close(fd_socks_ipv6);}
    if(fd_mng_ipv4 != -1){close(fd_mng_ipv4);}
    if(fd_mng_ipv6 != -1){close(fd_mng_ipv6);}
}

void
set_selector(fd_selector * new_selector){ selector = *new_selector; }

void
cleanup(){
    freeCpConnList();
    selector_destroy(selector); 
}