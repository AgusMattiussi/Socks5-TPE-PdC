#include "../stm/stm.h"
#include "../stm/buffer.h"

#include <netdb.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#define N(x) (sizeof(x)/sizeof((x)[0]))

enum socks_state{
    HELLO_READ,
    HELLO_WRITE,
    CONN_READ,
    CONN_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQ_READ,
    REQ_WRITE,
    REQ_RESOLVE,
    REQ_CONNECT,
    COPY,
    DONE,
    ERROR,
}

typedef struct socks_conn_model{
    struct sockaddr_storage cli_addr;
    socklen_t cli_addr_len;
    int cli_socket;

    struct sockaddr_storage src_addr;
    socklen_t src_addr_len;
    int src_socket;
    int src_domain;

    struct addrinfo * resolved_addr;
    struct addrinfo * curr_addr;


    // uint8_t * raw_buffer_[a|b]
    buffer read_buff;
    buffer write_buff;

    struct state_machine stm;

    // This parser will later become a auth or request, for now it is a connect parser
    struct conn_parser connect_parser;

    // POP3?

    //Aux structures for copy instance
    struct copy_model cli_copy;
    struct copy_model src_copy;

    const struct user * user;
} socks_conn_model;

