#include "../stm/stm.h"
#include "../buffer/buffer.h"

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
};

struct copy_model{
    int fd;
    buffer *read_buff;
    buffer *write_buff;
    fd_interest interests;
    fd_interest connection_interests;
    struct copy * other;
};

typedef struct socks_conn_model{
    struct sockaddr_storage cli_addr;
    socklen_t cli_addr_len;
    int cli_socket;
    int cli_interests; //Power of 2 mask defined in selector.h

    struct sockaddr_storage src_addr;
    socklen_t src_addr_len;
    int src_socket;
    int src_domain;
    int src_interests; 

    struct addrinfo * resolved_addr;
    struct addrinfo * curr_addr;

    buffer read_buff;
    buffer write_buff;

    //Check how to use according to Coda implementation
    uint8_t * aux_read_buff;
    uint8_t * aux_write_buff;

    struct state_machine stm;

    // This parser will later become a auth or request, for now it is a connect parser
    //  (Commented while it is in progress)
    struct conn_parser connect_parser;

    // POP3?

    //Aux structures for copy instance
    struct copy_model cli_copy;
    struct copy_model src_copy;

    const struct user * user;
} socks_conn_model;

struct state_definition * socks5_all_states();