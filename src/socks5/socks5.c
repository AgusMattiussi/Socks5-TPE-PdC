#include "socks5.h"

#define BUFFER_DEFAULT_SIZE 4096
uint32_t buf_size = BUFFER_DEFAULT_SIZE;
uint32_t socks_get_buf_size() { return buf_size; }

/*----------------------
 |  Connection functions
 -----------------------*/

void conn_read_init(const unsigned state, struct selector_key * key){
    printf("Llego a conn_read_init\n");
    struct socks_conn_model * connection = (socks_conn_model *)key->data;
    // TODO: Where to parse input? 
    // Update: We initialize parser when read is set
    start_connection_parser(connection->parsers->connect_parser);
}

static enum socks_state conn_read(struct selector_key * key){
    struct socks_conn_model * connection = (socks_conn_model *)key->data;
    struct conn_parser * parser = connection->parsers->connect_parser;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_write_ptr(&connection->buffers->read_buff, &byte_n);
    ssize_t n_received = recv(connection->cli_conn->socket, buff_ptr, byte_n, 0); //TODO:Flags?

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
    printf("Entro a connection write\n");
    socks_conn_model * connection = (socks_conn_model *) key->data;
    // We need to build the write the server response to buffer
    size_t n_available;
    uint8_t * buff_ptr = buffer_read_ptr(&connection->buffers->write_buff, &n_available);
    ssize_t n_sent = send(connection->cli_conn->socket, buff_ptr, n_available, 0); //TODO: Flags?
    if(n_sent == -1){
        fprintf(stdout, "Error sending bytes to client socket.");
        return ERROR;
    }
    printf("Mande %d bytes hacia cli\n", n_sent);
    buffer_read_adv(&connection->buffers->write_buff, n_sent);
    // We need to check whether there is something else to send. If so, we keep writing
    if(buffer_can_read(&connection->buffers->write_buff)){
        return CONN_WRITE;
    }

    // Nothing else to send. We set fd_interests and add to selector
    selector_status status = selector_set_interest_key(key, OP_READ);
    if(status != SELECTOR_SUCCESS) return ERROR;

    switch(connection->parsers->connect_parser->auth){
        case NO_AUTH:
            printf("STM pasa a estado REQ_READ\n");
            return REQ_READ;
        case USER_PASS:
            printf("STM pasa a estado AUTH_READ\n");
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


 void auth_read_init(const unsigned state, struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;
    printf("Llego a auth_read_init\n");
    auth_parser_init(connection->parsers->auth_parser);
 }

 static enum socks_state 
 auth_read(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct auth_parser * parser = connection->parsers->auth_parser;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_write_ptr(&connection->buffers->read_buff, &byte_n);
    ssize_t n_received = recv(connection->cli_conn->socket, buff_ptr, byte_n, 0); //TODO: Flags?
    if(n_received <= 0) return ERROR;
    buffer_write_adv(&connection->buffers->read_buff, n_received);

    enum auth_state ret_state = auth_parse_full(parser, &connection->buffers->read_buff);
    if(ret_state == AUTH_ERROR){
        fprintf(stdout, "Error parsing auth method");
        return ERROR;
    }
    if(ret_state == AUTH_DONE){ 
        //TODO: Build process_authentication_request (declared, not built yet)
        uint8_t is_authenticated = process_authentication_request((char*)parser->username, 
                                                                  (char*)parser->password);

        selector_status ret_selector = selector_set_interest_key(key, OP_WRITE);
        if(ret_selector != SELECTOR_SUCCESS) return ERROR;
        
        
        //TODO: Maybe move to auth_write method?
        size_t n_available;
        uint8_t * write_ptr = buffer_write_ptr(&connection->buffers->write_buff, &n_available);
        if(n_available < 2){
            fprintf(stdout, "Not enough space to send connection response.");
            return ERROR;
        }
        write_ptr[0] = AUTH_VERSION;
        write_ptr[1] = is_authenticated;
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
    ssize_t n_sent = send(connection->cli_conn->socket, buff_ptr, byte_n, 0); //TODO: Flags?
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
    snprintf(aux_buff, sizeof(aux_buff), "%d", ntohs(connection->parsers->req_parser->port));
    int ret = -1;
    struct addrinfo aux_hint = get_hint();
    ret = getaddrinfo((char *) connection->parsers->req_parser->addr.fqdn,
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
    int ret_thread_create = pthread_create(&thread_id, NULL, &name_resolving_thread, aux_key);
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
    connection->src_conn->socket = socket(connection->src_addr_family,
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
    enum socks_state state;
    switch(type){
        case IPv4:
        printf("IPv4\n");
            connection->src_addr_family = AF_INET;
            parser->addr.ipv4.sin_port = parser->port;
            connection->src_conn->addr_len = sizeof(parser->addr.ipv4);
            memcpy(&connection->src_conn->addr, &parser->addr.ipv4,
                                            sizeof(struct sockaddr_in));
            state = start_connection(parser, connection, key);
            return state;
        case IPv6:
        printf("IPv6\n");
            connection->src_addr_family = AF_INET6;
            parser->addr.ipv6.sin6_port = parser->port;
            connection->src_conn->addr_len = sizeof(struct sockaddr_in6);
            memcpy(&connection->src_conn->addr, &parser->addr.ipv6,
                                            sizeof(struct sockaddr_in6));
            state = start_connection(parser, connection, key);
            return state;
        case FQDN:
            printf("FQDN!!!\n");
            // Resolución de nombres --> Bloqueante! Usar threads
            return set_name_resolving_thread(key);
        case ADDR_TYPE_NONE:
            return ERROR;
        default: return ERROR;
    }
}

static void req_read_init(const unsigned state, struct selector_key * key){
    printf("Entro a req_read_init\n");
    struct socks_conn_model * connection = (socks_conn_model *) key->data;
    req_parser_init(connection->parsers->req_parser);
}

static enum socks_state 
req_read(struct selector_key * key){
    printf("Entro a req_read\n");
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct req_parser * parser = connection->parsers->req_parser;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_write_ptr(&connection->buffers->read_buff, &byte_n);
    ssize_t n_received = recv(connection->cli_conn->socket, buff_ptr, byte_n, 0); //TODO: Flags?
    if(n_received <= 0) return ERROR;
    buffer_write_adv(&connection->buffers->read_buff, n_received);

    enum req_state state = req_parse_full(parser, &connection->buffers->read_buff);
    printf("Salgo de parsear req, con estado: %d\n", state);
    if(state == REQ_ERROR){
        fprintf(stdout, "Error parsing request message");
        return ERROR;
    }
    if(state == REQ_DONE){
        enum req_cmd cmd = parser->cmd;
        switch(cmd){
            case REQ_CMD_CONNECT:
                printf("Manage_req_connection yendo\n");
                return manage_req_connection(connection, parser, key);
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
    struct req_parser * parser = connection->parsers->req_parser;
    if(connection->curr_addr != NULL){

        memcpy(&connection->src_conn->addr, connection->curr_addr->ai_addr,
                                connection->curr_addr->ai_addrlen);

        connection->src_addr_family = connection->curr_addr->ai_family;
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
    uint8_t * buff_ptr = buffer_write_ptr(write_buff, &byte_n);
    int addr_len = -1;
    enum req_atyp type = parser->res_parser.type;
    uint8_t * addr_ptr = NULL;
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
        *buff_ptr++ = *port_tokenizer++; //BND.PORT
        *buff_ptr++ = *port_tokenizer;
        buffer_write_adv(write_buff, (ssize_t)space_needed);
        return (int)space_needed;
    }
    return -1;
}

static enum socks_state 
req_connect(struct selector_key * key){
    printf("Entro a req_connect\n");
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct req_parser * parser = connection->parsers->req_parser;
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
            int domain = connection->src_addr_family;
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

static enum socks_state req_write(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct req_parser * parser = connection->parsers->req_parser;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_read_ptr(&connection->buffers->write_buff, &byte_n);
    ssize_t bytes_sent = send(connection->cli_conn->socket, buff_ptr, byte_n, 0); //TODO: Flags?
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

 /*----------------------------
 |  Copy functions
 ---------------------------*/

static void
set_copy_struct_config(int fd, struct copy_model_t * copy, 
                        buffer wr_buff, buffer rd_buff, struct copy_model_t * other_copy){
    copy->fd = fd;
    copy->buffers->write_buff = wr_buff;
    copy->buffers->read_buff = rd_buff;
    copy->interests = OP_READ;
    copy->connection_interests = OP_READ | OP_WRITE;
    copy->other = other_copy;
}

static void copy_init(const unsigned state, struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct copy_model_t * cli_copy = &connection->cli_copy;
    struct copy_model_t * src_copy = &connection->src_copy;

    //TODO: Chequear si hice esto bien, no me acuerdo.
    set_copy_struct_config(connection->cli_conn->socket, cli_copy, 
                            connection->buffers->write_buff,
                            connection->buffers->read_buff, src_copy);

    set_copy_struct_config(connection->src_conn->socket, src_copy,
                            connection->buffers->read_buff,
                            connection->buffers->write_buff, cli_copy);

    //TODO: No se que mas hay que configurar del copy pero dejo el TODO como marca
}

static enum socks_state copy_read(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct copy_model_t * copy = key->fd == connection->cli_conn->socket?
        &connection->cli_copy: key->fd == connection->src_conn->socket?
        &connection->src_copy: NULL;
    if(copy == NULL) return ERROR;

    if(buffer_can_write(&copy->buffers->write_buff)){
        size_t byte_n;
        uint8_t * buff_ptr = buffer_write_ptr(&copy->buffers->write_buff, &byte_n);
        ssize_t bytes_rcvd = recv(key->fd, buff_ptr, byte_n, 0); //TODO: Flags?
        if(bytes_rcvd > 0){
            buffer_write_adv(&copy->buffers->write_buff, bytes_rcvd);
            copy->other->interests = copy->other->interests | OP_WRITE;
            copy->other->interests = copy->other->interests & copy->other->connection_interests;
            selector_status selector_ret = 
                selector_set_interest(key->s, copy->other->fd, copy->other->interests);
            return selector_ret != SELECTOR_SUCCESS?ERROR:COPY;
        }
        uint8_t complement_mask = ~OP_READ;
        copy->connection_interests = copy->connection_interests & complement_mask;
        copy->interests = copy->interests & copy->connection_interests;
        selector_status selector_ret = selector_set_interest(key->s, copy->fd,
                                        copy->interests);
        if(selector_ret != SELECTOR_SUCCESS) return ERROR;
        //TODO: Close read copy.>fd connection. How to?
        // Solution: 
        // https://stackoverflow.com/questions/570793/how-to-stop-a-read-operation-on-a-socket
        // and (from top answer) man -s 2 shutdown
        int shutdown_ret = shutdown(copy->fd, SHUT_RD);
        if(shutdown_ret < 0){
            fprintf(stdout, "Shutdown failed");
            //return ERROR; //TODO: Should we return fail upon socket closure error?
        }
        //No more read for copy->fd socket
        if(!buffer_can_read(&(copy->buffers->write_buff))){
            copy->other->interests = copy->other->interests & 
                    copy->other->connection_interests;
            selector_status selector_ret = 
                    selector_set_interest(key->s, copy->other->fd, copy->other->interests);
            if(selector_ret != SELECTOR_SUCCESS) return ERROR;
            int shutdown_ret = shutdown(copy->other->fd, SHUT_WR);
            if(shutdown_ret < 0){
                fprintf(stdout, "Shutdown failed");
                //return ERROR; //TODO: Should we return fail upon socket closure error?
            }
            // No more write for copy->other->fd socket
        }
        return copy->connection_interests == OP_NOOP?
               (copy->other->connection_interests == OP_NOOP? DONE:COPY)
               :COPY;
    }
    // Switch interests
    uint8_t complement_mask = ~OP_READ; //OP_WRITE
    copy->interests = copy->interests & complement_mask; //TODO: Que pongo acá
    copy->interests = copy->interests & copy->connection_interests;
    //selector_status selector_ret = selector_set_interest(key->s, key->fd, copy->interests);
    selector_set_interest(key->s, key->fd, copy->interests);
    return COPY;
}

static enum socks_state copy_write(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *)key->data;
    struct copy_model_t * copy = key->fd == connection->cli_conn->socket?
        &connection->cli_copy: key->fd == connection->src_conn->socket?
        &connection->src_copy: NULL;
    if(copy == NULL) return ERROR;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_read_ptr(&copy->buffers->read_buff, &byte_n);
    ssize_t bytes_sent = send(key->fd, buff_ptr, byte_n, 0); //TODO: Flags?

    if(bytes_sent > 0){
        buffer_read_adv(&copy->buffers->read_buff, bytes_sent);
        copy->other->interests = copy->other->interests | OP_READ;
        copy->other->interests = copy->other->interests & copy->other->connection_interests;
        selector_status selector_ret = selector_set_interest(key->s, copy->other->fd, copy->other->interests);
        if(!buffer_can_read(&copy->buffers->read_buff)){
            uint8_t complement_mask = ~OP_WRITE;
            copy->interests = copy->interests & complement_mask;
            copy->interests = copy->interests & copy->other->interests;
            selector_ret = selector_set_interest(key->s, copy->fd, copy->interests);
            uint8_t should_close = copy->connection_interests & OP_WRITE;
            if(should_close == 0){
                shutdown(copy->fd, SHUT_WR);
            }
            return COPY;
        }
    }
    return ERROR; //TODO: error management?
}


//TODO: IMPORTANT! Define functions (where needed) for arrival, read, and write in states.
static const struct state_definition states[] = {
    /*{
        .state = HELLO_READ,
    },
    {
        .state = HELLO_WRITE,
    },*/
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
        .state = REQ_WRITE,
        .on_write_ready = req_write,
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
        .state = COPY,
        .on_arrival = copy_init,
        .on_read_ready = copy_read,
        .on_write_ready = copy_write,
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
