#include "socks5.h"
#include "../stm/stm.h"
#include "../selector/selector.h"
#include "../parsers/conn_parser.h"
#include "../parsers/auth_parser.h"
#include "../parsers/req_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

/*----------------------
 |  Connection functions
 -----------------------*/

void 
conn_read_init(struct selector_key * key){
    struct socks_conn_model * connection = (socks_conn_model *)key->data;
    // TODO: Where to parse input? 
    // Update: We initialize parser when read is set
    start_connection_parser(&connection->parsers->connect_parser);
}

static enum socks_state 
conn_read(struct selector_key * key){
    struct socks_conn_model * connection = (socks_conn_model *)key->data;
    struct conn_parser * parser = &connection->parsers->connect_parser;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_write_ptr(&connection->buffers->read_buff, &byte_n);
    ssize_t n_received = recv(connection->cli_conn->socket, buff_ptr, byte_n, NULL); //TODO:Flags?

    if(n_received <= 0) return ERROR;
    buffer_write_adv(&connection->buffers->read_buff, n_received);

    enum conn_state ret_state = conn_parse_full(parser, &connection->buffers->read_buff);
    if(ret_state == CONN_ERROR){
        fprintf(stderr, "Error while parsing.");
        return ERROR;
    }
    if(ret_state == CONN_DONE){
        // Nothing else to read, we move to writing
        selector_status ret_selector = selector_set_interest_key(key, OP_WRITE);
        //If finished, we need to create and send the srv response
        if(ret_selector == SELECTOR_SUCCESS){
            size_t n_available;
            uint8_t * write_ptr = buffer_write_ptr(&connection->buffers->write_buff, &n_available);
            if(n_available < 2){
                fprintf(stdout, "Not enough space to send connection response.");
                return ERROR;
            }
            write_ptr[0] = SOCKS_VERSION; write_ptr[1] = parser->auth;
            buffer_write_adv(&connection->buffers->write_buff, 2);
            return CONN_WRITE;
        }
        return ERROR;
    }
    //Not done yet
    return CONN_READ;
}

static enum socks_state 
conn_write(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    // We need to build the write the server response to buffer
    size_t n_available;
    uint8_t buff_ptr = buffer_read_ptr(&connection->buffers->write_buff, &n_available);
    ssize_t n_sent = send(connection->cli_conn->socket, buff_ptr, n_available, NULL); //TODO: Flags?
    if(n_sent == -1){
        fpritnf(stdout, "Error sending bytes to client socket.");
        return ERROR;
    }
    buffer_read_adv(&connection->buffers->write_buff, n_sent);
    // We need to check whether there is something else to send. If so, we keep writing
    if(buffer_can_read(&connection->buffers->write_buff)){
        return CONN_WRITE;
    }

    // Nothing else to send. We set fd_interests and add to selector
    selector_status status = selector_set_interest_key(key, OP_READ);
    if(status != SELECTOR_SUCCESS) return ERROR;

    switch(connection->parsers->connect_parser.auth){
        case NO_AUTH:
            return REQ_READ;
        case USER_PASS:
            return AUTH_READ;
        case GSSAPI:
            fprintf(stdout, "GSSAPI is out of this project's scope.");
            return DONE;
        case NO_METHODS:
            return DONE;
    }
    return ERROR;
}

/*----------------------------
 |  Authentication functions
 ---------------------------*/


 void 
 auth_read_init(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;
    auth_parser_init(&connection->parsers->auth_parser);
 }

 static enum socks_state 
 auth_read(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct auth_parser * parser = &connection->parsers->auth_parser;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_write_ptr(&connection->buffers->read_buff, &byte_n);
    ssize_t n_received = recv(connection->cli_conn->socket, buff_ptr, byte_n, NULL); //TODO: Flags?
    if(n_received <= 0) return ERROR;
    buffer_write_adv(&connection->buffers->read_buff, n_received);

    enum auth_state ret_state = auth_parse_full(parser, &connection->buffers->read_buff);
    if(ret_state == AUTH_ERROR){
        fprintf(stdout, "Error parsing auth method");
        return ERROR;
    }
    if(ret_state == AUTH_DONE){ 
        //TODO: Build process_authentication_request (declared, not built yet)
        uint8_t is_authenticated = process_authentication_request(&parser->username, 
                                                                  &parser->password);

        selector_status ret_selector = selector_set_interest_key(key, OP_WRITE);
        if(ret_selector != SELECTOR_SUCCESS) return ERROR;
        
        
        //TODO: Maybe move to auth_write method?
        size_t n_available;
        uint8_t * write_ptr = buffer_write_ptr(&connection->buffers->write_buff, &n_available);
        if(n_available < 2){
            fprintf(stdout, "Not enough space to send connection response.");
            return ERROR;
        }
        write_ptr[0] = AUTH_VERSION; write_ptr[1] = is_authenticated;
        buffer_write_adv(&connection->buffers->write_buff, 2);
        return AUTH_WRITE;
    }
    return AUTH_READ;
 }

 static enum socks_state 
 auth_write(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_read_ptr(&connection->buffers->write_buff, &byte_n);
    ssize_t n_sent = send(connection->cli_conn->socket, buff_ptr, byte_n, NULL); //TODO: Flags?
    if(n_sent <= 0) return ERROR;
    buffer_read_adv(&connection->buffers->write_buff, n_sent);
    if(buffer_can_read(&connection->buffers->write_buff)){
        return AUTH_WRITE;
    }
    selector_status ret_selector = selector_set_interest_key(key, OP_READ);
    return ret_selector == SELECTOR_SUCCESS? REQ_READ:ERROR;
 }

 /*----------------------------
 |  Request functions
 ---------------------------*/

#define FIXED_RES_BYTES 6

static struct addrinfo hint = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM,
    .ai_flags = AI_PASSIVE,
    .ai_protocol = 0,
    .ai_canonname = NULL,
    .ai_addr = NULL,
    .ai_next = NULL
};

struct addrinfo 
get_hint(){
    return hint;
}

static void 
clean_hint(){
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_PASSIVE;
    hint.ai_protocol = 0;
    hint.ai_canonname = NULL;
    hint.ai_addr = NULL;
    hint.ai_next = NULL;
}

static void *
name_resolving_thread(void * arg){
    struct selector_key * aux_key = (struct selector_key *) arg; 
    socks_conn_model * connection = (socks_conn_model *)aux_key->data;
    //TODO: Discutr un poco esto
    pthread_detach(pthread_self());
    char aux_buff[7];
    snprintf(aux_buff, sizeof(aux_buff), "%d", ntohs(connection->parsers->req_parser.port));
    int ret = -1;
    struct addrinfo aux_hint = get_hint();
    ret = getaddrinfo((char *) connection->parsers->req_parser.addr.fqdn,
                    aux_buff, &aux_hint, &connection->resolved_addr);
    if(ret != 0){
        fprintf(stdout, "Could not resolve FQDN.");
        freeaddrinfo(connection->resolved_addr);
        connection->resolved_addr = NULL;
    }
    clean_hint();
    connection->curr_addr = connection->resolved_addr;
    selector_notify_block(aux_key->s, aux_key->fd);
    free(arg);
    return 0;
}

static enum socks_state
set_name_resolving_thread(struct selector_key * key){
    struct selector_key * aux_key = malloc(sizeof(*key));
    if(aux_key == NULL){
        fprintf(stdout, "Error in malloc of aux_key");
        return ERROR; //TODO: Check error return
    }
    memcpy(aux_key, key, sizeof(*key));
    pthread_t thread_id;
    int ret_thread_create = pthread_create(thread_id, NULL, &name_resolving_thread, aux_key);
    if(ret_thread_create == 0){
        int ret_set_selector = selector_set_interest_key(key, OP_NOOP);
        return ret_set_selector == SELECTOR_SUCCESS?REQ_RESOLVE:ERROR;
    }
    free(aux_key);
    return ERROR; //TODO: Check error handling
}

static enum socks_state
start_connection(struct req_parser * parser, socks_conn_model * connection,
                    struct selector_key * key){
    connection->src_conn->socket = socket(connection->src_domain,
        SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(connection->src_conn->socket == -1){
        fprintf(stdout, "Socket creation failed");
        return ERROR;
    }
    int ret_conn = connect(connection->src_conn->socket, 
                            (struct sockaddr *) &connection->src_conn->addr,
                            connection->src_conn->addr_len);
    if(ret_conn == 0 || (ret_conn == -1 && errno == EINPROGRESS)){
        // Connection succesful
        selector_status ret_selector = selector_set_interest(key->s,
        connection->cli_conn->socket, OP_NOOP);
        if(ret_selector == SELECTOR_SUCCESS){
            ret_selector = -1;
            ret_selector = selector_register(key->s, connection->src_conn->socket,
                                            get_conn_actions_handler(), OP_WRITE, connection);
            return ret_selector == SELECTOR_SUCCESS?REQ_CONNECT:ERROR;
        }
        return ERROR; //TODO: Handle errors
    }
    return ERROR; //TODO: Handle errors

}

static enum socks_state
manage_req_connection(socks_conn_model * connection, struct req_parser * parser,
                        struct selector_key * key){
    enum req_atyp type = parser->type;
    switch(type){
        case IPv4:
            connection->src_domain = AF_INET;
            parser->addr.ipv4.sin_port = parser->port;
            connection->src_conn->addr_len = sizeof(parser->addr.ipv4);
            memcpy(&connection->src_conn->addr, &parser->addr.ipv4,
                                            sizeof(struct sockaddr_in));
            enum socks_state state = start_connection(parser, connection, key);
            return state;
        case IPv6:
            connection->src_domain = AF_INET6;
            parser->addr.ipv6.sin6_port = parser->port;
            connection->src_conn->addr_len = sizeof(struct sockaddr_in6);
            memcpy(&connection->src_conn->addr, &parser->addr.ipv6,
                                            sizeof(struct sockaddr_in6));
            enum socks_state state = start_connection(parser, connection, key);
            return state;
        case FQDN:
            // Resolución de nombres --> Bloqueante! Usar threads
            return set_name_resolving_thread(key);
        case ADDR_TYPE_NONE:
            return ERROR;
        default: return ERROR;
    }
}

void 
req_read_init(struct selector_key * key){
    struct socks_conn_model * connection = (socks_conn_model *) key->data;
    req_parser_init(&connection->parsers->req_parser);
}

static enum socks_state 
req_read(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct req_parser * parser = &connection->parsers->req_parser;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_write_ptr(&connection->buffers->read_buff, &byte_n);
    ssize_t n_received = recv(connection->cli_conn->socket, buff_ptr, byte_n, NULL); //TODO: Flags?
    if(n_received <= 0) return ERROR;
    buffer_write_adv(&connection->buffers->read_buff, n_received);

    enum req_state state = req_parse_full(parser, &connection->buffers->read_buff);
    if(state == REQ_ERROR){
        fprintf(stdout, "Error parsing request message");
        return ERROR;
    }
    if(state == REQ_DONE){
        enum req_cmd cmd = parser->cmd;
        switch(cmd){
            case REQ_CMD_CONNECT:
                manage_req_connection(connection, parser, key);
                //TODO: SEGUI ACA!!!
            case REQ_CMD_BIND:
                fprintf(stdout, "REQ_CMD_BIND not supported in this implementation");
                return ERROR;
            case REQ_CMD_UDP:
                fprintf(stdout, "REQ_CMD_UDP not supported in this project");
                return ERROR;
            case REQ_CMD_NONE:
                fprintf(stdout, "REQ_CMD_NONE nunca debería ocurrir?");
                return ERROR; //TODO: esto no estoy seguro
        }
    }
    //TODO: Me suena que nunca debería llegar acá, osea tiene que fallar de antemano para que
    // salga del parseo y llegue hasta acá. Charlar.
    return REQ_READ;
}

static enum socks_state
req_resolve(struct selector_key * key){
    // Post thread completition state, we need to start the connection to the address
    // resolved in start_connection();
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct req_parser * parser = &connection->parsers->req_parser;
    if(connection->curr_addr != NULL){

        memcpy(&connection->src_conn->addr, connection->curr_addr->ai_addr,
                                connection->curr_addr->ai_addrlen);

        connection->src_domain = connection->curr_addr->ai_family;
        connection->src_conn->addr_len = connection->curr_addr->ai_addrlen;

        connection->curr_addr = connection->curr_addr->ai_next;

        return start_connection(parser, connection, key);
    }
    //Name was not resolved correctly
    fprintf(stdout, "thread's name resolution failed!");
    if(connection->resolved_addr != NULL){
        connection->curr_addr = NULL;
        freeaddrinfo(connection->resolved_addr);
        connection->resolved_addr = NULL;
    }
    return ERROR;
}

static enum socks_state
req_write(struct selector_key * key){

    return ERROR;
}

static int 
create_response(struct req_parser * parser, buffer * write_buff){
    /*
    Reminder of response structure:
    +----+-----+-------+------+----------+----------+
 *       |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *       +----+-----+-------+------+----------+----------+
 *       | 1  |  1  | X'00' |  1   | Variable |    2     |
 *       +----+-----+-------+------+----------+----------+
 * (https://www.rfc-editor.org/rfc/rfc1928)
    */ 
    size_t byte_n;
    uint8_t * buff_ptr = buffer_write_ptr(write_buff, byte_n);
    int addr_len = -1;
    enum req_atyp type = parser->res_parser.type;
    uint8_t addr_ptr = NULL;
    if(type == IPv4){
        addr_len = IPv4_BYTES;
        addr_ptr = (uint8_t *) &(parser->res_parser.addr.ipv4.sin_addr);
    }
    else if(type == IPv6){
        addr_len = IPv6_BYTES;
        addr_ptr = parser->res_parser.addr.ipv6.sin6_addr.s6_addr;
    }
    else if(type == FQDN){
        addr_len = strlen((char *) parser->res_parser.addr.fqdn);
        addr_ptr = parser->res_parser.addr.fqdn; 
    }
    else{
        fprintf(stdout, "No compatible type recognized: %d", type);
        return -1;
    }
    size_t space_needed = FIXED_RES_BYTES + addr_len + (type==FQDN?1:0);
    if(byte_n >= space_needed && addr_ptr != NULL){
         // If type is FQDN, we need to declare the amount of octets of the name
        *buff_ptr++ = SOCKS_VERSION; //VER
        *buff_ptr++ = parser->res_parser.state; //REP
        *buff_ptr++ = 0x00; //REV
        *buff_ptr++ = type; //ATYP
        if(type==FQDN) *buff_ptr++ = addr_len; //Octet n
        strncpy((char*)buff_ptr, (char*)addr_ptr, addr_len); //BND.ADDR
        buff_ptr += addr_len;
        uint8_t * port_tokenizer = (uint8_t *) &(parser->res_parser.port);
        *buff_ptr++ = *port_tokenizer++;
        *buff_ptr++ = *port_tokenizer;
        buffer_write_adv(write_buff, (ssize_t)space_needed);
        return (int)space_needed;
    }


    return -1;
}

static enum socks_state
req_connect(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct req_parser * parser = &connection->parsers->req_parser;
    unsigned int error = 0;
    int getsockopt_retval = -1;
    getsockopt_retval = getsockopt(connection->src_conn->socket,
                                    SOL_SOCKET, SO_ERROR, &error,
                                    &(socklen_t){sizeof(unsigned int)});
    if(getsockopt_retval == 0){
        if(!error){
            if(parser->type == FQDN){
                freeaddrinfo(connection->resolved_addr);
                connection->resolved_addr = NULL;
            }
            parser->res_parser.state = RES_SUCCESS;
            parser->res_parser.port = parser->port;
            int domain = connection->src_domain;
            if(domain != AF_INET && domain != AF_INET6){
                fprintf(stdout, "Domain is unrecognized");
                return ERROR; //TODO: Check error management
            }
            if(domain == AF_INET){
                parser->res_parser.type = IPv4;
                memcpy(&parser->res_parser.addr, &connection->src_conn->addr, 
                    sizeof(struct sockaddr_in));
            }
            else{
                //IPv6
                parser->res_parser.type = IPv6;
                memcpy(&parser->res_parser.addr, &connection->src_conn->addr,
                        sizeof(struct sockaddr_in6));
            }
            int selector_ret = -1;
            selector_ret = selector_set_interest_key(key, OP_NOOP);
            if(selector_ret == SELECTOR_SUCCESS){
                selector_ret = selector_set_interest(key->s, connection->cli_conn->socket,
                                    OP_WRITE);
                if(selector_ret == SELECTOR_SUCCESS){
                    int bytes_written = 
                                create_response(parser, &connection->buffers->write_buff);
                    if(bytes_written > -1){
                        return REQ_WRITE;
                    }
                }
            }
            return ERROR;
        }
    }
    if(parser->type == FQDN){
        freeaddrinfo(connection->resolved_addr);
        connection->resolved_addr = NULL;
    }
    return ERROR;
}

static enum socks_state
req_write(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct req_parser * parser = &connection->parsers->req_parser;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_read_ptr(&connection->buffers->write_buff, &byte_n);
    ssize_t bytes_sent = send(connection->cli_conn->socket, buff_ptr,
                            byte_n, NULL); //TODO: Flags?
    if(bytes_sent == -1){
        fprintf(stdout, "Sending bytes in req_write failed");
        return ERROR;
    }

    buffer_read_adv(&connection->buffers->write_buff, bytes_sent);
    if(buffer_can_read(&connection->buffers->write_buff)) return REQ_WRITE;
    if(parser->res_parser.state != RES_SUCCESS) return DONE; // No copy to do now, just end the connection
    selector_status selector_ret = selector_set_interest_key(key, OP_READ);
    if(selector_ret==SELECTOR_SUCCESS){
        selector_ret = selector_set_interest(key->s, connection->src_conn->socket,
                                            OP_READ);
        return selector_ret==SELECTOR_SUCCESS?COPY:ERROR;
    }
    return ERROR;
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
        .on_write_ready = conn_write,
    },
    {
        .state = AUTH_READ,
        .on_arrival = auth_read_init,
        .on_read_ready = auth_read,
    },
    {
        .state = AUTH_WRITE,
        .on_write_ready = auth_write,
    },
    {
        .state = REQ_READ,
        .on_arrival = req_read_init,
        .on_read_ready = req_read,
    },
    {
        .state = REQ_RESOLVE,
        .on_block_ready = req_resolve,
    },
    {
        .state = REQ_CONNECT,
        .on_write_ready = req_connect,
    },
    {
        .state = REQ_WRITE,
        .on_write_ready = req_write,
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
