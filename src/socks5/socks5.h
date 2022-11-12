#include "../stm/stm.h"
#include "../buffer/buffer.h"
#include "../parsers/conn_parser.h"
#include "../parsers/auth_parser.h"
#include "../parsers/req_parser.h"

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

struct std_conn_model{
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int socket;
    int interests;
};

struct buffers_t{
    buffer read_buff;
    buffer write_buff;

    uint8_t * aux_read_buff;
    uint8_t * aux_write_buff;
};

struct parsers_t{
    struct conn_parser connect_parser;
    struct auth_parser auth_parser;
    struct req_parser req_parser;
};

typedef struct socks_conn_model{

    struct std_conn_model * cli_conn;
    struct std_conn_model * src_conn;
    int src_domain;

    struct buffers_t * buffers;
    struct parsers_t * parsers;

    struct addrinfo * resolved_addr;
    struct addrinfo * curr_addr;

    struct state_machine stm;

    // POP3?

    //Aux structures for copy instance
    struct copy_model cli_copy;
    struct copy_model src_copy;

    const struct user * user;
} socks_conn_model;

struct state_definition * socks5_all_states();