#ifndef MNG_H
#define MNG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "../socks5/socks5.h"
#include "../include/stm.h"
#include "../include/buffer.h"
#include "../include/selector.h"
#include "../include/server.h"
#include "../parsers/conn_parser.h"
#include "../parsers/auth_parser.h"
#include "../parsers/req_parser.h"
#include "../users/user_mgmt.h" 


enum mng_state {
    MNG_CONN_READ,
    MNG_CONN_WRITE,
    MNG_AUTH_READ,
    MNG_AUTH_WRITE,
    MNG_REQ_READ,
    MNG_REQ_WRITE,
    MNG_ERROR,
    MNG_DONE
};

typedef struct mng_conn_model {
    struct std_conn_model * cli_conn;
    int src_addr_family;

    struct buffers_t * buffers;
    struct parsers_t * parsers;

    struct state_machine stm;
} mng_conn_model;

struct state_definition * mng_all_states();

#endif