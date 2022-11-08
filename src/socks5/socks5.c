#include "socks5.h"
#include "../stm/stm.h"
#include "../selector/selector.h"
#include "../parsers/conn_parser.h"

#include <stdio.h>
#include <stdlib.h>

void conn_read_init(struct selector_key * key){
    struct socks_conn_model * connection = (socks_conn_model *)key->data;
    // TODO: Where to parse input? 
    // Update: We initialize parser when read is set
    start_connection_parser(&connection->connect_parser);
}

static enum socks_state conn_read(struct selector_key * key){
    struct socks_conn_model * connection = (socks_conn_model *)key->data;
    struct conn_parser * parser = &connection->connect_parser;
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

    enum conn_state ret_state = conn_parse_full(parser, &connection->read_buff);
    if(ret_state == ERROR){
        fprintf(stderr, "Error while parsing.");
        return ERROR;
    }
    if(parser->state == DONE){
        // Nothing else to read, we move to writing
        selector_status ret_selector = selector_set_interest_key(key, OP_WRITE);
        //If finished, we need to create and send the srv response
        if(ret_selector == SELECTOR_SUCCESS){
            size_t n_available;
            uint8_t * write_ptr = buffer_write_ptr(&connection->write_buff, &n_available);
            if(n_available < 2){
                fprintf(stdout, "Not enough space to send connection response.");
                return ERROR;
            }
            write_ptr[0] = SOCKS_VERSION; write_ptr[1] = parser->auth;
            buffer_write_adv(&connection->write_buff, 2);
            return CONN_WRITE;
        }
    }
    //Not done yet
    return CONN_READ;
}





//TODO: IMPORTANT! Define functions (where needed) for arrival, read, and write in states.
static const struct state_definition states[] = {
    {
        .state = HELLO_READ,
    },
    {
        .state = HELLO_WRITE,
    },
    {
        .state = CONN_READ,
        .on_arrival = conn_read_init,
        .on_read_ready = conn_read,
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
