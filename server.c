#include "src/buffer/buffer.h"
#include "src/netutils/netutils.h"
#include "src/parser/parser_utils.h"
#include "src/parser/parser.h"
#include "src/selector/selector.h"
#include "src/stm/stm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>  
#include <math.h>  


#include "server.h"
#include "selector.h"

#define INITIAL_N 20
#define MAX_QUEUE 50

//TODO (General): Set error codes in all goto finally calls.

static void passive_socks_socket_handler(struct selector_key * key);

static fd_selector selector;

const struct fd_handler passive_socket_fd_handler = {passive_socks_socket_handler, 0,
                                                     0, 0};


static void passive_socks_socket_handler(struct selector_key * key){
    /*



    TODO: Build passive socket handler for socks connection




    */
}

static int start_socket(unsigned short port, char * addr, const struct * fd_handler handler, int family){
    int ret_fd;
    
    struct addrinfo hints; 
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
    struct addrinfo * res = NULL;

    //TODO: Check if itoa() of unsigned short works
    char buff[256];
    int base = 10;
    char * service;
    service = itoa(port, buff, base);

    int ret_addrinfo;
    ret_addrinfo = getaddrinfo(addr, service, &hints, &res);
    if(ret_addrinfo != 0){goto finally;}

    ret_fd = socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if(ret_fd == -1){goto finally;}

    //Reuse address
    int ret_setsockopt = -1;
    ret_setsockopt = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    if(ret_setsockopt == -1){goto finally;}

    //Set for IPv6 if necessary
    if(family == AF_INET6){
        int ret_setsockopt_ipv6;
        ret_setsockopt_ipv6 = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int));
        if(ret_setsockopt_ipv6 == -1){goto finally;}
    }

    int ret_bind = bind(fd, res->ai_addr, res-_ai_addrlen);
    if(ret_bind < 0){goto finally;}

    int ret_listen = listen(fd, MAX_QUEUE);
    it(ret_listen < 0){goto finally;}

    int ret_register;
    ret_register = selector_register(selector, fd, handler, OP_READ, NULL);
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
    select_timeout.tv_sec = SELECTOR_TIMEOUT;
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
        //TODO: Set an error message
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