#include "include/server.h"
#include "logger/logger.h"
#include "include/metrics.h"

#define INITIAL_N 20
#define MAX_QUEUE 50
#define BUFF_SIZE 2048

static fd_selector selector;

static void passive_socks_socket_handler(struct selector_key * key);

const struct fd_handler passive_socket_fd_handler = {
    .handle_read = passive_socks_socket_handler, 
    .handle_write = 0, 
    .handle_block = 0, 
    .handle_close = 0};

const struct fd_handler connection_actions_handler = { 
    .handle_read = socks_connection_read,
    .handle_write = socks_connection_write,
    .handle_block = socks_connection_block,
    .handle_close = socks_connection_close
};

const struct fd_handler * 
get_conn_actions_handler() {
    return &connection_actions_handler;
}

void 
close_socks_conn(socks_conn_model * connection) {
    if(connection->guardian){
        return;
    }
    connection->guardian = true;

    int client_socket = connection->cli_conn->socket;
    int server_socket = connection->src_conn->socket;

    if (server_socket != -1) {
        selector_unregister_fd(selector, server_socket);
        close(server_socket);
    }
    if (client_socket != -1) {
        remove_current_socks_connection();    
        selector_unregister_fd(selector, client_socket);
        close(client_socket);
    }
    if (connection->resolved_addr != NULL) {
        freeaddrinfo(connection->resolved_addr);
    }

    buffer_reset(&connection->buffers->read_buff);
    buffer_reset(&connection->buffers->write_buff);

    free(connection->buffers->aux_read_buff);
    free(connection->buffers->aux_write_buff);
    free(connection);
}

static void passive_socks_socket_handler(struct selector_key * key){
    //TODO: Check if enough fds are available

    socks_conn_model * connection = malloc(sizeof(struct socks_conn_model));
    if(connection == NULL) { 
        perror("error:");
        return; 
    }
    memset(connection, 0x00, sizeof(*connection));

    connection->cli_conn = malloc(sizeof(struct std_conn_model));
    connection->src_conn = malloc(sizeof(struct std_conn_model));
    memset(connection->cli_conn, 0x00, sizeof(*(connection->cli_conn)));
    memset(connection->src_conn, 0x00, sizeof(*(connection->src_conn)));

    connection->parsers = malloc(sizeof(struct parsers_t));
    memset(connection->parsers, 0x00, sizeof(*(connection->parsers)));

    connection->parsers->connect_parser = malloc(sizeof(struct conn_parser));
    connection->parsers->auth_parser = malloc(sizeof(struct auth_parser));
    connection->parsers->req_parser = malloc(sizeof(struct req_parser));
    memset(connection->parsers->connect_parser, 0x00, sizeof(*(connection->parsers->connect_parser)));
    memset(connection->parsers->auth_parser, 0x00, sizeof(*(connection->parsers->auth_parser)));
    memset(connection->parsers->req_parser, 0x00, sizeof(*(connection->parsers->req_parser)));

    connection->buffers = malloc(sizeof(struct buffers_t));
    connection->buffers->aux_read_buff = malloc((uint32_t)BUFF_SIZE);
    connection->buffers->aux_write_buff = malloc((uint32_t)BUFF_SIZE);

    buffer_init(&connection->buffers->read_buff, BUFF_SIZE, connection->buffers->aux_read_buff);
    buffer_init(&connection->buffers->write_buff, BUFF_SIZE, connection->buffers->aux_write_buff);

    //State Machine parameter setting
    connection->stm.initial = CONN_READ;
    connection->stm.max_state = DONE;
    connection->stm.states = socks5_all_states();

    stm_init(&connection->stm);
    connection->cli_conn->interests = OP_READ;
    connection->src_conn->interests = OP_NOOP;
    //After setting up the configuration, we accept the connection
    connection->cli_conn->addr_len = sizeof(connection->cli_conn->addr);
    connection->cli_conn->socket = accept(key->fd, (struct sockaddr *)&connection->cli_conn->addr,
    &connection->cli_conn->addr_len);
    if(connection->cli_conn->socket == -1){
        LogError("Error in accept call");
        close_socks_conn(connection);
        return;
    }
 
    int sel_ret = selector_fd_set_nio(connection->cli_conn->socket);
    if(sel_ret == -1){
        LogError("Error in selector_fd_set_nio call");
        close_socks_conn(connection);
        return;
    }
    
    selector_status sel_register_ret = selector_register(selector, connection->cli_conn->socket,
        &connection_actions_handler, OP_READ, connection);
    if(sel_register_ret != SELECTOR_SUCCESS){
        LogError("Error in selector_fregister call: %s",
        selector_error(sel_register_ret));
        close_socks_conn(connection);
        return;
    }
    add_socks_connection();
}

static int start_socket(char * port, char * addr, 
                        const struct fd_handler * handler, int family){
    int ret_fd;
    struct addrinfo hints; //Naming corresponding to fields in 'man getaddrinfo'
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
    struct addrinfo * res = NULL;
    int error = 0;

    int ret_addrinfo;
    ret_addrinfo = getaddrinfo(addr, port, &hints, &res);
    if(ret_addrinfo){
        LogError("Error en getaddrinfo. %s", gai_strerror(ret_addrinfo));
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
    if(family == AF_INET6){
        int ret_setsockopt_ipv6;
        ret_setsockopt_ipv6 = setsockopt(ret_fd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int));
        if(ret_setsockopt_ipv6 == -1){
            LogError("Error setstockopt");
            perror("socket");
            error=-1;
            goto finally;
        }
    }

    int ret_bind = bind(ret_fd, res->ai_addr, res->ai_addrlen);
    if(ret_bind < 0){
        LogError("Error in bind call");
        perror("bind");
        goto finally;
        }

    int ret_listen = listen(ret_fd, MAX_QUEUE);
    if(ret_listen < 0){ 
        LogError("Error in listen call");
        perror("listen");
        error=-1;
        goto finally; 
    }

    int ret_register;
    ret_register = selector_register(selector, ret_fd, handler, OP_READ, NULL);
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

//static void network_selector_signal_handler() { printf("SIGCHLD SIGNAL"); }


int start_server(char * socks_addr, char * socks_port){
    int fd_socks_ipv4 = -1, fd_socks_ipv6 = -1;
    int ret_code = -1;

    //Initialization of selector struct
    struct timespec select_timeout = {0};
    select_timeout.tv_sec = 100;
    struct selector_init select_init_struct = {SIGCHLD, select_timeout};

    // Configure the selector
    int selector_init_retvalue = -1;
    selector_init_retvalue = selector_init(&select_init_struct);
    if(selector_init_retvalue != SELECTOR_SUCCESS){
        LogError("Selector initialization failed: %s",
        selector_error(selector_init_retvalue));
        goto finally;
    }  

    // Initialize the selector
    selector = selector_new(INITIAL_N);
    if(selector == NULL){
        LogError("Selector creation failed");
        goto finally;
    }

    fd_socks_ipv4 = start_socket(socks_port, socks_addr, &passive_socket_fd_handler, AF_UNSPEC);
    if(fd_socks_ipv4 == -1){ 
        LogError("Failed to start IPv4 socket");
        goto finally; 
    }
    else if(socks_addr == NULL){
        fd_socks_ipv6 = start_socket(socks_port, NULL, &passive_socket_fd_handler, AF_INET6);
        if(fd_socks_ipv6 == -1){
            LogError("Failed to start IPv6 socket");
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
    return ret_code;

}

void
cleanup(){
    selector_destroy(selector);
}