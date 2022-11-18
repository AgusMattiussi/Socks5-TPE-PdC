#include "include/server.h"


#define INITIAL_N 20
#define MAX_QUEUE 50
#define BUFF_SIZE 2048

//TODO (General): Set error codes in all goto finally calls.

static void passive_socks_socket_handler(struct selector_key * key);
static void passive_mng_socket_handler(struct selector_key * key);
static void passive_cp_socket_handler(struct selector_key * key) ;

static fd_selector selector;

const struct fd_handler passive_socket_fd_handler = {passive_socks_socket_handler, 0, 0, 0};
//TODO: Should this functions have a &? 

const struct fd_handler passive_socket_fd_mng_handler = {passive_cp_socket_handler, 0, 0, 0};

const struct fd_handler mng_connection_actions_handler = { 
    mng_connection_read, mng_connection_write,
    mng_connection_block, mng_connection_close
};

const struct fd_handler connection_actions_handler = { 
    socks_connection_read,socks_connection_write,
    socks_connection_block,socks_connection_close
};

const struct fd_handler * get_mng_conn_actions_handler() {
    return &mng_connection_actions_handler;
}

const struct fd_handler * get_conn_actions_handler() {
    return &connection_actions_handler;
}

void close_socks_conn(socks_conn_model * connection) {
    int client_socket = connection->cli_conn->socket;
    int server_socket = connection->src_conn->socket;

    if (server_socket != -1) {
        selector_unregister_fd(selector, server_socket);
        close(server_socket);
    }
    if (client_socket != -1) {
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

static void passive_mng_socket_handler(struct selector_key * key){
    
    printf("Entre al socket handler de MNG conexión entrante...\n");
    mng_conn_model * connection = malloc(sizeof(struct mng_conn_model));
    if(connection == NULL) { 
        perror("error:");
        return; 
    }
    memset(connection, 0x00, sizeof(*connection));
    
    connection->cli_conn = malloc(sizeof(struct std_conn_model));
    memset(connection->cli_conn, 0x00, sizeof(*(connection->cli_conn)));

    
    connection->parsers = malloc(sizeof(struct parsers_t));
    memset(connection->parsers, 0x00, sizeof(*(connection->parsers)));

    connection->parsers->connect_parser = malloc(sizeof(struct conn_parser));
    connection->parsers->auth_parser = malloc(sizeof(struct auth_parser));
    connection->parsers->req_parser = malloc(sizeof(struct req_parser));
    memset(connection->parsers->connect_parser, 0x00, sizeof(*(connection->parsers->connect_parser)));
    memset(connection->parsers->auth_parser, 0x00, sizeof(*(connection->parsers->auth_parser)));
    memset(connection->parsers->req_parser, 0x00, sizeof(*(connection->parsers->req_parser)));

    printf("Inicializo buffers auxiliares\n");
    connection->buffers = malloc(sizeof(struct buffers_t));
    connection->buffers->aux_read_buff = malloc((uint32_t)BUFF_SIZE);
    connection->buffers->aux_write_buff = malloc((uint32_t)BUFF_SIZE);

    printf("Paso mallocs de inicialización de buffers\n");

    buffer_init(&connection->buffers->read_buff, BUFF_SIZE, connection->buffers->aux_read_buff);
    buffer_init(&connection->buffers->write_buff, BUFF_SIZE, connection->buffers->aux_write_buff);

    printf("Inicialize buffers\n");
    //State Machine parameter setting
    connection->stm.initial = MNG_CONN_READ;
    connection->stm.max_state = MNG_DONE;
    connection->stm.states = mng_all_states();
    stm_init(&connection->stm);
    printf("Vuelvo de stm init\n");
    connection->cli_conn->interests = OP_READ;
    printf("Incialización de stm...\n");
    //After setting up the configuration, we accept the connection
    connection->cli_conn->addr_len = sizeof(connection->cli_conn->addr);
    printf("Llegue hasta linea previa de accept\n");
    connection->cli_conn->socket = accept(key->fd, (struct sockaddr *)&connection->cli_conn->addr,
    &connection->cli_conn->addr_len);
    printf("Pase el accept\n");
    if(connection->cli_conn->socket == -1){
        printf("Error in accept call of line 49 in passive_socks\n");
        //TODO: close_socks5_connection(connection);
        close_socks_conn(connection);
        return;
    }
 
    int sel_ret = selector_fd_set_nio(connection->cli_conn->socket);
    if(sel_ret == -1){
        printf("Error in selector_fd_set_nio call of line 57 in passive_socks\n");
        close_socks_conn(connection);
        //TODO: close_socks5_connection(connection);
        return;
    }
    
    
    selector_status sel_register_ret = selector_register(selector, connection->cli_conn->socket,
    get_mng_conn_actions_handler(), OP_READ, connection);
    if(sel_register_ret != SELECTOR_SUCCESS){
        printf("Error in selector_fregister call of line 66 in passive_socks\n");
        close_socks5_connection(connection);
        //close_socks5_connection(connection);
        return;
    }
    printf("Salgo de start socket aparentemente sin errores!\n");
}

static void dummyFunction(struct selector_key * key){
    printf("\n DUMMY \n");
}

const fd_handler cpFdHandler = {
    .handle_read = dummyFunction,
    .handle_write = dummyFunction,
    .handle_block = dummyFunction,
    .handle_close = dummyFunction
};


static void passive_cp_socket_handler(struct selector_key * key) {
    printf(" En passive_cp_socket_handler\n");
    controlProtConn * new;
    
    /* Aceptamos la conexion entrante */
    int clientFd = accept(key->fd, NULL, NULL);
    if(clientFd < 0){
        //TODO: Manejar error (Juli)
        printf(" ERROR en passive_cp_socket_handler (accept)\n");
        return;
    }

    /* Hacemos el socket no bloqueante */
    if(selector_fd_set_nio(clientFd) == -1){
        // TODO: Manejar error (Juli)
        printf(" ERROR en passive_cp_socket_handler (selector_fd_set_nio)\n");
        return;
    }

    /* Inicializamos la estructura con los datos de esta conexion */
    // TODO: Considerar aniadirlo a una lista?
    new = newControlProtConn(clientFd);
    if(new == NULL){
        //TODO: Manejar error (Juli)
        printf(" ERROR en passive_cp_socket_handler (newControlProtConn)\n");
        return;
    }

    if(selector_register(key->s, new->fd, /*TODO:*/ &cpFdHandler, new->interests, new) != 0){
        //TODO: Manejar error (Juli)
        printf(" ERROR en passive_cp_socket_handler (selector_register)\n");
        return;
    }

    printf(" Socket pasivo creado exitosamente \n");
}

static void passive_socks_socket_handler(struct selector_key * key){
    //TODO: Check if enough fds are available
    // TODO: Aca hay un error ¿¿¿??? Recibe SIGSEGV pero no entiendo por que,
    // con el perror anterior verificamos que pasa bien el malloc
    // Fui probando de cambiar el orden de cierta inicialización de los parametros pero el 
    // SIGSEGV llega en momentos pseudo aleatorios?
    printf("Entre al socket handler de conexión entrante...\n");
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



    printf("Inicializo buffers auxiliares\n");
    connection->buffers = malloc(sizeof(struct buffers_t));
    connection->buffers->aux_read_buff = malloc((uint32_t)BUFF_SIZE);
    connection->buffers->aux_write_buff = malloc((uint32_t)BUFF_SIZE);

    printf("Paso mallocs de inicialización de buffers\n");

    buffer_init(&connection->buffers->read_buff, BUFF_SIZE, connection->buffers->aux_read_buff);
    buffer_init(&connection->buffers->write_buff, BUFF_SIZE, connection->buffers->aux_write_buff);

    printf("Inicialize buffers\n");
    //State Machine parameter setting
    connection->stm.initial = CONN_READ;
    connection->stm.max_state = DONE;
    connection->stm.states = socks5_all_states();

    stm_init(&connection->stm);
    printf("Vuelvo de stm init\n");
    connection->cli_conn->interests = OP_READ;
    connection->src_conn->interests = OP_NOOP;
    printf("Incialización de stm...\n");
    //After setting up the configuration, we accept the connection
    connection->cli_conn->addr_len = sizeof(connection->cli_conn->addr);
    printf("Llegue hasta linea previa de accept\n");
    connection->cli_conn->socket = accept(key->fd, (struct sockaddr *)&connection->cli_conn->addr,
    &connection->cli_conn->addr_len);
    printf("Pase el accept\n");
    if(connection->cli_conn->socket == -1){
        printf("Error in accept call of line 49 in passive_socks\n");
        //TODO: close_socks5_connection(connection);
        close_socks_conn(connection);
        return;
    }
 
    int sel_ret = selector_fd_set_nio(connection->cli_conn->socket);
    if(sel_ret == -1){
        printf("Error in selector_fd_set_nio call of line 57 in passive_socks\n");
        close_socks_conn(connection);
        //TODO: close_socks5_connection(connection);
        return;
    }
    
    
    selector_status sel_register_ret = selector_register(selector, connection->cli_conn->socket,
    get_conn_actions_handler(), OP_READ, connection);
    if(sel_register_ret != SELECTOR_SUCCESS){
        printf("Error in selector_fregister call of line 66 in passive_socks\n");
        close_socks5_connection(connection);
        //close_socks5_connection(connection);
        return;
    }
    printf("Salgo de start socket aparentemente sin errores!\n");
}

static int start_socket(char * port, char * addr, 
                        const struct fd_handler * handler, int family){
    int ret_fd;
    printf("Entro a start socket\n");

    struct addrinfo hints; //Naming corresponding to fields in 'man getaddrinfo'
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
    struct addrinfo * res = NULL;

    //TODO: Check if sprintf of unsigned short works
    /*char service[256];
    int base = 10;
    sprintf(service, "%d", port);
    printf("%s\n", service);*/

    int ret_addrinfo;
    ret_addrinfo = getaddrinfo(addr, port, &hints, &res);
    if(ret_addrinfo){
        printf("Error en getaddrinfo \n");
        printf("%s", gai_strerror(ret_addrinfo));
        goto finally;
    }

    ret_fd = socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if(ret_fd == -1){
        printf("Error creating socket in call of line 96\n");
        perror("socket");
        goto finally;    
    }

    //Reuse address
    int ret_setsockopt = -1;
    ret_setsockopt = setsockopt(ret_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    if(ret_setsockopt == -1){
        printf("Error setstockopt in call of line 105\n");
        perror("socket");
        goto finally;    
    }

    //Set for IPv6 if necessary
    if(family == AF_INET6){
        printf("Family is IPv6\n");
        int ret_setsockopt_ipv6;
        ret_setsockopt_ipv6 = setsockopt(ret_fd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int));
        if(ret_setsockopt_ipv6 == -1){
            printf("Error setstockopt in call of line 115\n");
            perror("socket");
            goto finally;
        }
    }

    int ret_bind = bind(ret_fd, res->ai_addr, res->ai_addrlen);
    if(ret_bind < 0){
        printf("Error bind in call of line 123\n");
        perror("bind");
        goto finally;
        }

    int ret_listen = listen(ret_fd, MAX_QUEUE);
    if(ret_listen < 0){ 
        printf("Error listen in call of line 130\n");
        perror("listen");
        goto finally; 
    }

    int ret_register;
    ret_register = selector_register(selector, ret_fd, handler, OP_READ, NULL);
    if(ret_register != SELECTOR_SUCCESS){
        printf("Error selector_register in call of line 138\n");
        goto finally;
    }
    printf("Termine ejecución de create_socket correctamente!\n");
finally:
    freeaddrinfo(res);
    return ret_fd;

}

static void network_selector_signal_handler() { printf("SIGCHLD SIGNAL"); }


int start_server(char * socks_addr, char * socks_port, char * mng_addr, char * mng_port){
    printf("Entro a start server\n");
    int fd_socks_ipv4 = -1, fd_socks_ipv6 = -1, fd_mng_ipv4 = -1, fd_mng_ipv6 = -1;
    int ret_code = -1;

    signal(SIGCHLD, network_selector_signal_handler);

    //Initialization of selector struct
    struct timespec select_timeout = {0};
    select_timeout.tv_sec = 100;
    struct selector_init select_init_struct = {SIGCHLD, select_timeout};

    // Configure the selector
    int selector_init_retvalue = -1;
    selector_init_retvalue = selector_init(&select_init_struct);
    if(selector_init_retvalue != SELECTOR_SUCCESS){
        printf("Falle en linea 134 de start_server\n");
        fprintf(stderr, "Selector initialization failed. %s",
        selector_error(selector_init_retvalue));
        goto finally;
    }  

    // Initialize the selector
    selector = selector_new(INITIAL_N);
    if(selector == NULL){
        printf("Falle en linea 143 de start_server\n");
        fprintf(stderr, "Selector creation failed.");
        goto finally;
    }

    fd_socks_ipv4 = start_socket(socks_port, socks_addr, &passive_socket_fd_handler, AF_UNSPEC);
    if(fd_socks_ipv4 == -1){ 
        printf("Falle en start_socket ipv4, linea 150 de start_server\n");
        goto finally; }
    else if(socks_addr == NULL){
        fd_socks_ipv6 = start_socket(socks_port, NULL, &passive_socket_fd_handler, AF_INET6);
        if(fd_socks_ipv6 == -1){
            printf("Falle en start socket ipv6, linea 155 de start_server\n");
            goto finally; 
        }
    }
    fd_mng_ipv4 = start_socket(mng_port, mng_addr, &passive_socket_fd_mng_handler, AF_UNSPEC);
    if(fd_mng_ipv4 == -1){ 
        printf("Falle en start_socket ipv4, linea 150 de start_server\n");
        goto finally; }
    else if(mng_addr == NULL){
        fd_mng_ipv6 = start_socket(mng_port, NULL, &passive_socket_fd_mng_handler, AF_INET6);
        if(fd_mng_ipv6 == -1){
            printf("Falle en start socket ipv6, linea 155 de start_server\n");
            goto finally; 
        }
    }

    

    while(1){
        printf("Entre al superloop de start server\n");
        int selector_ret_value = selector_select(selector);
        if(selector_ret_value != SELECTOR_SUCCESS){goto finally;}
    }

finally:
    if(fd_socks_ipv4 != -1){close(fd_socks_ipv4);}
    if(fd_socks_ipv6 != -1){close(fd_socks_ipv6);}
    return ret_code;

}