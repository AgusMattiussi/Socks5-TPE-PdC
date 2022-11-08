#include "socks5.h"
#include "../stm/stm.h"
#include "../selector/selector.h"

void conn_read_init(struct selector_key * key){
    struct socks_conn_model * connection = (socks_conn_model *)key->data;
    // TODO: Where to parse input? 
}

static enum socks_state conn_read(struct selector_key * key){
    struct socks_conn_model * connection = (socks_conn_model *)key->data;

    // We need to receive bytes from socket (use recv for this)
    // Reminder: buff_w_ptr sets in byte_n the amount of available space to write in buffer
    // This must then be notified via the method buffer_write_adv so that the system registers
    // this bytes will be written

    size_t byte_n;
    uint8_t * buff_ptr = buffer_write_ptr(&connection->read_buff, &byte_n);
    ssize_t n_received = recv(connection->cli_socket, buff_ptr, byte_n, NULL); //Flags?

    if(n_received <= 0) return ERROR;
    buffer_write_adv(&connection->read_buff, n_received);

    // TODO: Now we need to parse the input we receive and set the appropiate
    // return state.

}





//TODO: IMPORTANT! Define functions (where needed) for arrival, read, and write in states.
static const struct state_definition states[] = {
    {
        .state = HELLO_READ,
        .on_arrival = conn_read_init,
        .on_read_ready = conn_read,
    },
    {
        .state = HELLO_WRITE,
    },
    {
        .state = CONN_READ,
    },
    {
        .state = CONN_WRITE,
    },
    {
        .state = AUTH_READ,
    },
    {
        .state = AUTH_WRITE,
    },
    {
        .state = REQ_READ,
    },
    {
        .state = REQ_RESOLVE,
    },
    {
        .state = REQ_CONNECT,
    },
    {
        .state = REQ_WRITE,
    },
    {
        .state = COPY,
    },
    {
        .state = ERROR,
    },
    {
        .state = DONE,
    }
};

struct state_definition * socks5_all_states(){
    return states;
}
