#include "src/buffer/buffer.h"
#include "src/netutils/netutils.h"
#include "src/parser/parser_utils.h"
#include "src/parser/parser.h"
#include "src/selector/selector.h"
#include "src/stm/stm.h"
#include "src/socks5/socks5.h"
#include "src/conn_handler.h"

#include <sys/signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>  
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "server.h"
#include "selector.h"

#define INITIAL_N 20
#define MAX_QUEUE 50
#define BUFF_SIZE 4096

//TODO (General): Set error codes in all goto finally calls.

static void passive_socks_socket_handler(struct selector_key * key);

static fd_selector selector;

const struct fd_handler passive_socket_fd_handler = {passive_socks_socket_handler, 0, 0, 0};
//TODO: Should this functions have a &? 
const struct fd_handler connection_actions_handler = 
{socks_connection_read,socks_connection_write,
socks_connection_block,socks_connection_close};


static void passive_socks_socket_handler(struct selector_key * key){
    //TODO: Check if enough fds are available
    socks_conn_model * connection = malloc(sizeof(struct socks_conn_model));
    if(connection == NULL) { return; }
    memset(connection, 0, sizeof(*connection));

    connection->cli_conn->interests = OP_READ;
    connection->src_conn->interests = OP_NOOP;

    connection->buffers->aux_read_buff = malloc(BUFF_SIZE);
    connection->buffers->aux_write_buff = malloc(BUFF_SIZE);
    buffer_init(&connection->buffers->read_buff, BUFF_SIZE, connection->buffers->aux_read_buff);
    buffer_init(&connection->buffers->write_buff, BUFF_SIZE, connection->buffers->aux_write_buff);

    //State Machine parameter setting
    connection->stm.initial = CONN_READ;
    connection->stm.max_state = DONE;
    connection->stm.states = socks5_all_states();
    stm_init(&connection->stm);

    //After setting up the configuration, we accept the connection
    connection->cli_conn->addr_len = sizeof(connection->cli_conn->addr);
    connection->cli_conn->socket = accept(key->fd, (struct sockaddr *)&connection->cli_conn->addr,
    &connection->cli_conn->addr_len);
    if(connection->cli_conn->socket == -1){
        //TODO: close_socks5_connection(connection);
        return;
    }
 
    int sel_ret = selector_fd_set_nio(connection->cli_conn->socket);
    if(sel_ret == -1){
        //TODO: close_socks5_connection(connection);
        return;
    }
    
    
    selector_status sel_register_ret = selector_register(selector, connection->cli_conn->socket,
    &connection_actions_handler, OP_READ, connection);
    if(sel_register_ret != SELECTOR_SUCCESS){
        //close_socks5_connection(connection);
        return;
    }
}

static int start_socket(unsigned short port, char * addr, 
                        const struct fd_handler * handler, int family){
    int ret_fd;
    
    struct addrinfo hints; //Naming corresponding to fields in 'man getaddrinfo'
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
    struct addrinfo * res = NULL;

    //TODO: Check if itoa() of unsigned short works
    char service[256];
    int base = 10;
    sprintf(service, "%d", port);
    printf(service);

    int ret_addrinfo;
    ret_addrinfo = getaddrinfo(addr, service, &hints, &res);
    if(ret_addrinfo != 0){goto finally;}

    ret_fd = socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if(ret_fd == -1){goto finally;}

    //Reuse address
    int ret_setsockopt = -1;
    ret_setsockopt = setsockopt(ret_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    if(ret_setsockopt == -1){goto finally;}

    //Set for IPv6 if necessary
    if(family == AF_INET6){
        int ret_setsockopt_ipv6;
        ret_setsockopt_ipv6 = setsockopt(ret_fd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int));
        if(ret_setsockopt_ipv6 == -1){goto finally;}
    }

    int ret_bind = bind(ret_fd, res->ai_addr, res->ai_addrlen);
    if(ret_bind < 0){goto finally;}

    int ret_listen = listen(ret_fd, MAX_QUEUE);
    if(ret_listen < 0){ goto finally; }

    int ret_register;
    ret_register = selector_register(selector, ret_fd, handler, OP_READ, NULL);
    if(ret_register != SELECTOR_SUCCESS){goto finally;}

finally:
    freeaddrinfo(res);
    return ret_fd;

}

int start_server(char * socks_addr, unsigned short socks_port){
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
        fprintf(stderr, "Selector initialization failed. %s",
        selector_error(selector_init_retvalue));
        goto finally;
    }  

    // Initialize the selector
    selector = selector_new(INITIAL_N);
    if(selector == NULL){
        fprintf(stderr, "Selector creation failed.");
        goto finally;
    }

    fd_socks_ipv4 = start_socket(socks_port, socks_addr, &passive_socket_fd_handler, AF_UNSPEC);
    if(fd_socks_ipv4 == -1){ goto finally; }
    else if(socks_addr == NULL){
        fd_socks_ipv6 = start_socket(socks_port, NULL, &passive_socket_fd_handler, AF_INET6);
        if(fd_socks_ipv6 == -1){goto finally; }
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