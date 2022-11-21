#include "socks5.h"

#define CLI 0
#define SRC 1
#define BUFF_SIZE 2048 // 

/*----------------------
 |  Helping functions
 -----------------------*/

static int 
check_buff_and_receive(buffer * buff_ptr, int socket){
    size_t byte_n;
    uint8_t * write_ptr = buffer_write_ptr(buff_ptr, &byte_n);
    ssize_t n_received = recv(socket, write_ptr, byte_n, 0); //TODO:Flags?
    if(n_received <= 0) return -1;
    buffer_write_adv(buff_ptr, n_received);
    return n_received;
}

static int 
check_buff_and_send(buffer * buff_ptr, int socket){
    size_t n_available;
    uint8_t * read_ptr = buffer_read_ptr(buff_ptr, &n_available);
    ssize_t n_sent = send(socket, read_ptr, n_available, 0); //TODO: Flags?
    if(n_sent == -1){ return -1; }
    buffer_read_adv(buff_ptr, n_sent);
    return n_sent;
}


/*----------------------
 |  Connection functions
 -----------------------*/


static enum socks_state hello_read(struct selector_key * key){
    
    if(key == NULL)
        return ERROR;

    struct socks_conn_model * socks = (socks_conn_model *)key->data;
    start_connection_parser(socks->parsers->connect_parser);

    if(check_buff_and_receive(&socks->buffers->read_buff,
                                    socks->cli_conn->socket) == -1){ return ERROR; }

    struct conn_parser * parser = socks->parsers->connect_parser;
    enum conn_state ret_state = conn_parse_full(parser, &socks->buffers->read_buff);
    if(ret_state == CONN_ERROR){
        LogError("Error while parsing.");
        return ERROR;
    }
    if(ret_state == CONN_DONE){
        selector_status ret_selector = selector_set_interest_key(key, OP_WRITE);
        if(ret_selector == SELECTOR_SUCCESS){
            size_t n_available;
            uint8_t * write_ptr = buffer_write_ptr(&socks->buffers->write_buff, &n_available);
            if(n_available < 2){
                LogError("Not enough space to send socks response.");
                return ERROR;
            }
            *write_ptr++ = SOCKS_VERSION; *write_ptr = parser->auth;
            buffer_write_adv(&socks->buffers->write_buff, 2);
            return HELLO_WRITE;
        }
        return ERROR;
    }
    return HELLO_READ;
}


static enum socks_state 
hello_write(struct selector_key * key){

    if(key == NULL)
        return ERROR;

    socks_conn_model * socks = (socks_conn_model *) key->data;

    if(check_buff_and_send(&socks->buffers->write_buff, socks->cli_conn->socket) == -1){
        LogError("Error sending bytes to client socket.");
        return ERROR;
    }

    if(buffer_can_read(&socks->buffers->write_buff)){
        return HELLO_WRITE;
    }

    selector_status status = selector_set_interest_key(key, OP_READ);
    if(status != SELECTOR_SUCCESS) return ERROR;

    switch(socks->parsers->connect_parser->auth){
        case NO_AUTH:
            LogDebug("STM pasa a estado REQ_READ\n");
            return REQ_READ;
        case USER_PASS:
            LogDebug("STM pasa a estado AUTH_READ\n");
            return AUTH_READ;
        case GSSAPI:
            LogDebug("GSSAPI is out of this project's scope.");
            return DONE;
        case NO_METHODS:
            return DONE;
    }
    return ERROR;
}

/*----------------------------
 |  Authentication functions
 ---------------------------*/

 static enum socks_state 
 auth_read(struct selector_key * key){

    if(key == NULL)
        return ERROR;

    socks_conn_model * socks = (socks_conn_model *)key->data;
    auth_parser_init(socks->parsers->auth_parser);

    if(check_buff_and_receive(&socks->buffers->read_buff,
                                    socks->cli_conn->socket) == -1){ return ERROR; }

    struct auth_parser * parser = socks->parsers->auth_parser;
    enum auth_state ret_state = auth_parse_full(parser, &socks->buffers->read_buff);
    if(ret_state == AUTH_ERROR){
        LogError("Error parsing auth method");
        return ERROR;
    }
    if(ret_state == AUTH_DONE){ 
        uint8_t is_authenticated = process_authentication_request((char*)parser->username, 
                                                                  (char*)parser->password);
        /*if(is_authenticated == -1){
            LogError("Error authenticating user. Username or password are incorrect, or user does not exist. Exiting.\n");
            
            return ERROR;
        }*/
        set_curr_user((char*)parser->username);
        selector_status ret_selector = selector_set_interest_key(key, OP_WRITE);
        if(ret_selector != SELECTOR_SUCCESS) return ERROR;        
        size_t n_available;
        uint8_t * write_ptr = buffer_write_ptr(&socks->buffers->write_buff, &n_available);
        if(n_available < 2){
            LogError("Not enough space to send connection response.");
            return ERROR;
        }
        write_ptr[0] = AUTH_VERSION;
        write_ptr[1] = is_authenticated;
        buffer_write_adv(&socks->buffers->write_buff, 2);
        return AUTH_WRITE;
    }
    return AUTH_READ;
}


static enum socks_state 
auth_write(struct selector_key * key){
    socks_conn_model * socks = (socks_conn_model *)key->data;

    if(check_buff_and_send(&socks->buffers->write_buff, socks->cli_conn->socket) == -1){
        LogError("Error sending bytes to client socket.");
        return ERROR;
    }

    if(buffer_can_read(&socks->buffers->write_buff)){
        return AUTH_WRITE;
    }
    selector_status ret_selector = selector_set_interest_key(key, OP_READ);
    return ret_selector == SELECTOR_SUCCESS? REQ_READ:ERROR;
}

 /*----------------------------
 |  Request functions
 ---------------------------*/

 #define FIXED_RES_BYTES 6

static int
req_response_message(buffer * write_buff, struct res_parser * parser){
    size_t n_bytes;
    uint8_t * buff_ptr = buffer_write_ptr(write_buff, &n_bytes);
    uint8_t * addr_ptr = NULL; 
    enum req_atyp addr_type = parser->type;

    size_t length = addr_type == IPv4? IPv4_BYTES:
                    (addr_type == IPv6)? IPv6_BYTES:
                    (addr_type == FQDN)? strlen((char *)parser->addr.fqdn):
                    0;
    addr_ptr = addr_type == IPv4? (uint8_t *)&(parser->addr.ipv4.sin_addr):
                    (addr_type == IPv6)? parser->addr.ipv6.sin6_addr.s6_addr:
                    (addr_type == FQDN)? parser->addr.fqdn:
                    NULL;
    if(length == 0 || addr_ptr == NULL){
        LogError("Error detecting address type.");
        return -1;
    }

    size_t space_needed = length + FIXED_RES_BYTES + (parser->type==FQDN);
    if (n_bytes < space_needed) {
        LogError("Insufficient space to create response");
        return -1;
    }

    *buff_ptr++ = SOCKS_VERSION;
    *buff_ptr++ = parser->state;
    *buff_ptr++ = 0x00;
    *buff_ptr++ = addr_type;
    if (addr_type == FQDN) {
        *buff_ptr++ = length;
    }

    strncpy((char *)buff_ptr, (char *)addr_ptr, length);
    buff_ptr += length;
    uint8_t * port_ptr = (uint8_t *)&(parser->port);
    *buff_ptr++ = port_ptr[0];
    *buff_ptr++ = port_ptr[1];

    buffer_write_adv(write_buff, (ssize_t)space_needed);
    return (int)space_needed;
}

static void
set_res_parser(struct req_parser * parser, /* enum socks_state */ unsigned socks_state){
    parser->res_parser.state = socks_state;
    parser->res_parser.type = parser->type;
    parser->res_parser.port = parser->port;
    parser->res_parser.addr = parser->addr;
}

static enum socks_state 
manage_req_error(struct req_parser * parser, /* enum socks_state */ unsigned socks_state,
                socks_conn_model * conn, struct selector_key * key) {
    set_res_parser(parser, socks_state);
    selector_status selector_ret = selector_set_interest(key->s, conn->cli_conn->socket, OP_WRITE);
    int response_created = req_response_message(&conn->buffers->write_buff, &parser->res_parser);
    return ((selector_ret == SELECTOR_SUCCESS) && (response_created != -1))?REQ_WRITE:ERROR;
}

static enum socks_state 
init_connection(struct req_parser * parser, socks_conn_model * socks, struct selector_key * key) {
    socks->src_conn->socket = socket(socks->src_addr_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (socks->src_conn->socket == -1) {
        return ERROR;
    }
    int connect_ret = connect(socks->src_conn->socket, 
        (struct sockaddr *)&socks->src_conn->addr, socks->src_conn->addr_len);
    if(connect_ret == 0 || ((connect_ret != 0) && (errno == EINPROGRESS))){ 
        int selector_ret = selector_set_interest(key->s, socks->cli_conn->socket, OP_NOOP);
        if(selector_ret != SELECTOR_SUCCESS) {return ERROR;}
        selector_ret = selector_register(key->s, socks->src_conn->socket, 
                            get_conn_actions_handler(), OP_WRITE, socks);
        if(selector_ret != SELECTOR_SUCCESS){return ERROR;}
        return REQ_CONNECT;
    }
    LogError("Initializing connection failure");
    perror("Connect failed due to: ");
    return manage_req_error(parser, errno_to_req_response_state(errno), socks, key);
}

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
req_dns_thread(void * arg){
    struct selector_key * aux_key = (struct selector_key *) arg; 
    socks_conn_model * socks = (socks_conn_model *)aux_key->data;

    pthread_detach(pthread_self());
    
    char aux_buff[7];
    snprintf(aux_buff, sizeof(aux_buff), "%d", ntohs(socks->parsers->req_parser->port));
    int ret_getaddrinfo = -1;
    struct addrinfo aux_hint = get_hint();
    ret_getaddrinfo = getaddrinfo((char *) socks->parsers->req_parser->addr.fqdn,
                    aux_buff, &aux_hint, &socks->resolved_addr);
    if(ret_getaddrinfo != 0){
        LogError("Could not resolve FQDN.");
        freeaddrinfo(socks->resolved_addr);
        socks->resolved_addr = NULL;
    }
    clean_hint();
    socks->curr_addr = socks->resolved_addr;
    selector_notify_block(aux_key->s, aux_key->fd);
    free(arg);
    return 0;
}


static enum socks_state
set_connection(socks_conn_model * socks, struct req_parser * parser, enum req_atyp type,
                struct selector_key * key){
    if(type == IPv4){
        socks->src_addr_family = AF_INET;
        parser->addr.ipv4.sin_port = parser->port;
        socks->src_conn->addr_len = sizeof(parser->addr.ipv4);
        memcpy(&socks->src_conn->addr, &parser->addr.ipv4, sizeof(parser->addr.ipv4));
    }
    else if(type == IPv6){
        socks->src_addr_family = AF_INET6;
        parser->addr.ipv6.sin6_port = parser->port;
        socks->src_conn->addr_len = sizeof(parser->addr.ipv6);
        memcpy(&socks->src_conn->addr, &parser->addr.ipv6, sizeof(parser->addr.ipv6));
    }
    else if(type == FQDN){
        struct selector_key * aux_key = malloc(sizeof(*key));
        if (aux_key == NULL) {
            LogError("Malloc failure for aux_key instantiation\n");
            return manage_req_error(parser, RES_SOCKS_FAIL, socks, key);
        }
        memcpy(aux_key, key, sizeof(*key));
        pthread_t tid;
        int thread_create_ret = pthread_create(&tid, NULL, &req_dns_thread, aux_key);
        if (thread_create_ret !=0 ){
            free(aux_key);
            return manage_req_error(parser, RES_SOCKS_FAIL, socks, key);
        }
        selector_status selector_ret = selector_set_interest_key(key, OP_NOOP);
        if (selector_ret != SELECTOR_SUCCESS) { return ERROR; }
        return REQ_DNS;
    }
    else{
        LogError("Unknown connection type\n");
        return ERROR;
    }
    return init_connection(parser, socks, key);
}

static enum socks_state 
req_read(struct selector_key * key) {
    socks_conn_model * socks = (socks_conn_model *)key->data;
    req_parser_init(socks->parsers->req_parser);

    if(check_buff_and_receive(&socks->buffers->read_buff,
                                    socks->cli_conn->socket) == -1){ return ERROR; }

    struct req_parser * parser = socks->parsers->req_parser;
    enum req_state parser_state = req_parse_full(parser, &socks->buffers->read_buff);
    if (parser_state == REQ_DONE) {
        switch (parser->cmd) {
            case REQ_CMD_CONNECT:
                return set_connection(socks, parser, parser->type, key);
            case REQ_CMD_BIND:
            case REQ_CMD_UDP:
                return manage_req_error(parser, RES_CMD_UNSUPPORTED, socks, key);
            case REQ_CMD_NONE:
                return DONE;
            default:
                LogError("Unknown request command type\n");
                return ERROR;
        }
    }
    if (parser_state == REQ_ERROR){ return ERROR; }
    return REQ_READ;
}


static enum socks_state 
req_dns(struct selector_key * key) {
    socks_conn_model * socks = (socks_conn_model *)key->data;
    struct req_parser * parser = socks->parsers->req_parser;

    if (socks->curr_addr == NULL) {
        if (socks->resolved_addr != NULL) {
            freeaddrinfo(socks->resolved_addr);
            socks->resolved_addr = NULL;
            socks->curr_addr = NULL;
        }
        return manage_req_error(parser, RES_HOST_UNREACHABLE, socks, key);
    }

    socks->src_addr_family = socks->curr_addr->ai_family;
    socks->src_conn->addr_len = socks->curr_addr->ai_addrlen;
    memcpy(&socks->src_conn->addr, socks->curr_addr->ai_addr,
           socks->curr_addr->ai_addrlen);
    socks->curr_addr = socks->curr_addr->ai_next;

    return init_connection(parser, socks, key);
}


static void
clean_resolved_addr(socks_conn_model * socks){
    freeaddrinfo(socks->resolved_addr);
    socks->resolved_addr = NULL;
}

static int
set_response(struct req_parser * parser, int addr_family, socks_conn_model * socks){
    parser->res_parser.state = RES_SUCCESS;
    parser->res_parser.port = parser->port;
    switch (addr_family) {
        case AF_INET:
            parser->res_parser.type = IPv4;
            memcpy(&parser->res_parser.addr.ipv4, &socks->src_conn->addr,
                sizeof(parser->res_parser.addr.ipv4));
            break;
        case AF_INET6:
            parser->res_parser.type = IPv6;
            memcpy(&parser->res_parser.addr.ipv6, &socks->src_conn->addr,
                sizeof(parser->res_parser.addr.ipv6));
            break;
        default:
            return -1;
    }
    return 0;
}


static enum socks_state 
req_connect(struct selector_key * key) {
    socks_conn_model * socks = (socks_conn_model *)key->data;
    struct req_parser * parser = socks->parsers->req_parser;
    int optval = 0;
    int getsockopt_ret = getsockopt(socks->src_conn->socket, SOL_SOCKET, 
                            SO_ERROR, &optval, &(socklen_t){sizeof(int)});
    if(getsockopt_ret == 0){
        if(optval != 0){
            if (parser->type == FQDN) {
                selector_unregister_fd(key->s, socks->src_conn->socket, false);
                close(socks->src_conn->socket);
                return req_dns(key);
            }
            return manage_req_error(parser, errno_to_req_response_state(optval), socks, key);
        }
        if(parser->type == FQDN){ clean_resolved_addr(socks);}
        int ret_val = set_response(parser, socks->src_addr_family, socks);
        if(ret_val == -1){ return manage_req_error(parser, RES_SOCKS_FAIL, socks, key);}
        selector_status selector_ret = selector_set_interest_key(key, OP_NOOP);
        if(selector_ret == 0){
            selector_ret = selector_set_interest(key->s, socks->cli_conn->socket, OP_WRITE);
            if(selector_ret == 0){
                ret_val = req_response_message(&socks->buffers->write_buff, &parser->res_parser);
                if(ret_val != -1){ return REQ_WRITE; }
            }
        }
        return ERROR;
    }
    if(parser->type == FQDN){ clean_resolved_addr(socks);}
    return manage_req_error(parser, RES_SOCKS_FAIL, socks, key);
}


static enum socks_state 
req_write(struct selector_key * key) {
    socks_conn_model * socks = (socks_conn_model *)key->data;
    struct req_parser * parser = socks->parsers->req_parser;

    if(check_buff_and_send(&socks->buffers->write_buff, socks->cli_conn->socket) == -1){
        LogError("Error sending bytes to client socket.");
        return ERROR;
    }


    conn_information(socks);
    if(buffer_can_read(&socks->buffers->write_buff)){ return REQ_WRITE; }
    if(parser->res_parser.state != RES_SUCCESS){return DONE; }
    selector_status selector_ret = selector_set_interest_key(key, OP_READ);
    if(selector_ret == SELECTOR_SUCCESS){
        selector_ret = selector_set_interest(key->s, socks->src_conn->socket, OP_READ);
        return selector_ret == SELECTOR_SUCCESS?COPY:ERROR;
    }
    return ERROR;
}

static int
init_copy_structure(socks_conn_model * socks, struct copy_model_t * copy,
                    int which){
    if(which == CLI){
        copy->fd = socks->cli_conn->socket;
        copy->read_buff = &socks->buffers->read_buff;
        copy->write_buff = &socks->buffers->write_buff;
        copy->aux = &socks->src_copy;
    }
    else if(which == SRC){
        copy->fd = socks->src_conn->socket;
        copy->read_buff = &socks->buffers->write_buff;
        copy->write_buff = &socks->buffers->read_buff;
        copy->aux = &socks->cli_copy;
    }
    else{
        LogError("Error initializng copy structures\n");
        return -1;
    }
    copy->interests = OP_READ;
    copy->int_connection = OP_READ | OP_WRITE;
    return 0;
}

static void 
copy_on_arrival(unsigned state, struct selector_key * key) {
    socks_conn_model * socks = (socks_conn_model *)key->data;
    struct copy_model_t * copy = &socks->cli_copy;
    int init_ret = init_copy_structure(socks, copy, CLI);
    if(init_ret == -1){
        LogError("Error initializng copy structures\n");
        //return ERROR;
    }
    copy = &socks->src_copy;
    init_ret = init_copy_structure(socks, copy, SRC);
    if(init_ret == -1){
        LogError("Error initializng copy structures\n");
        //return ERROR;
    }

    if(sniffer_is_on()){
        socks->pop3_parser = malloc(sizeof(pop3_parser));
        pop3_parser_init(socks->pop3_parser); 
        if(socks->pop3_parser == NULL)
            LogError("Pop3Parser is null\n");    
    }
}
static struct copy_model_t *
get_copy(int fd, int cli_sock, int src_sock, socks_conn_model * socks){
    return fd == cli_sock? &socks->cli_copy:
           fd == src_sock? &socks->src_copy:
           NULL;
}

static enum socks_state 
copy_read(struct selector_key * key) {
    socks_conn_model * socks = (socks_conn_model *)key->data;
    struct copy_model_t * copy = get_copy(key->fd, socks->cli_conn->socket, 
                                    socks->src_conn->socket, socks);
    if(copy == NULL){
        LogError("Copy is null\n");
        return ERROR;
    }
    if(buffer_can_write(copy->write_buff)){
        int bytes_read = check_buff_and_receive(copy->write_buff, key->fd);
        if(bytes_read == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)){
            return COPY;
        }

        if(bytes_read > 0){
            copy->aux->interests = copy->aux->interests | OP_WRITE;
            copy->aux->interests = copy->aux->interests & copy->aux->int_connection;
            selector_set_interest(key->s, copy->aux->fd, copy->aux->interests); //TODO: Capture error?

            if(ntohs(socks->parsers->req_parser->port) == POP3_PORT && 
                socks->pop3_parser != NULL && sniffer_is_on()){
                if(pop3_parse(socks->pop3_parser, copy->write_buff) == POP3_DONE){
                    pass_information(socks);
                }
            }
            return COPY;
        }

        
        copy->int_connection = copy->int_connection & ~OP_READ;
        copy->interests = copy->interests & copy->int_connection;
        selector_set_interest(key->s, copy->fd, copy->interests); //TODO: Capture selector error?
        // https://stackoverflow.com/questions/570793/how-to-stop-a-read-operation-on-a-socket
        // man -s 2 shutdown
        shutdown(copy->fd, SHUT_RD);
        copy->aux->int_connection = 
            copy->aux->int_connection & OP_READ;
        
        if(!buffer_can_read(copy->write_buff)){
            copy->aux->interests &= copy->aux->int_connection;
            selector_set_interest(key->s, copy->aux->fd, copy->aux->interests);
            shutdown(copy->aux->fd, SHUT_WR);
        }


        return copy->int_connection == OP_NOOP?
                (copy->aux->int_connection == OP_NOOP?
                DONE:COPY):COPY;
    }
    copy->interests = (copy->interests & OP_WRITE) & copy->int_connection;
    selector_set_interest(key->s, key->fd, copy->interests);
    return COPY;
}
static enum socks_state 
copy_write(struct selector_key * key) {
    socks_conn_model * socks = (socks_conn_model *)key->data;
    struct copy_model_t * copy = get_copy(key->fd, socks->cli_conn->socket, 
                                    socks->src_conn->socket, socks);
    if(copy == NULL){
        LogError("Copy is null\n");
        return ERROR;
    }

    int bytes_sent = check_buff_and_send(copy->read_buff, key->fd);
    if(bytes_sent == -1){
        if(errno == EWOULDBLOCK || errno == EAGAIN){ return COPY; }
        LogError("Error sending bytes to client socket.");
        return ERROR;
    }

    //buffer_read_adv(copy->read_buff, bytes_sent);
    add_bytes_transferred((long)bytes_sent);
    copy->aux->interests = (copy->aux->interests | OP_READ) & copy->aux->int_connection;
    selector_set_interest(key->s, copy->aux->fd, copy->aux->interests); //TODO: Capture return?

    if (!buffer_can_read(copy->read_buff)) {
        copy->interests = (copy->interests & OP_READ) & copy->int_connection;
        selector_set_interest(key->s, copy->fd, copy->interests);
        uint8_t still_write = copy->int_connection & OP_WRITE;
        if(still_write == 0){
            shutdown(copy->fd, SHUT_WR);
        }
    }
    return COPY;
}

static const struct state_definition states[] = {
    {
        .state = HELLO_READ,
        .on_read_ready = hello_read,
    },
    {
        .state = HELLO_WRITE,
        .on_write_ready = hello_write,
    },
    {
        .state = AUTH_READ,
        .on_read_ready = auth_read,
    },
    {
        .state = AUTH_WRITE,
        .on_write_ready = auth_write,
    },
    {
        .state = REQ_READ,
        .on_read_ready = req_read,
    },
    {
        .state = REQ_WRITE,
        .on_write_ready = req_write,
    },
    {
        .state = REQ_DNS,
        .on_block_ready = req_dns,
    },
    {
        .state = REQ_CONNECT,
        .on_write_ready = req_connect,
    },
    {
        .state = COPY,
        .on_arrival = copy_on_arrival,
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

socks_conn_model * 
new_socks_conn() {
    socks_conn_model * socks = malloc(sizeof(struct socks_conn_model));
    if(socks == NULL) { 
        perror("error:");
        return NULL; 
    }
    memset(socks, 0x00, sizeof(*socks));

    socks->cli_conn = malloc(sizeof(struct std_conn_model));
    socks->src_conn = malloc(sizeof(struct std_conn_model));
    memset(socks->cli_conn, 0x00, sizeof(*(socks->cli_conn)));
    memset(socks->src_conn, 0x00, sizeof(*(socks->src_conn)));
    socks->cli_conn->interests = OP_READ;
    socks->src_conn->interests = OP_NOOP;

    socks->parsers = malloc(sizeof(struct parsers_t));
    memset(socks->parsers, 0x00, sizeof(*(socks->parsers)));

    socks->parsers->connect_parser = malloc(sizeof(struct conn_parser));
    socks->parsers->auth_parser = malloc(sizeof(struct auth_parser));
    socks->parsers->req_parser = malloc(sizeof(struct req_parser));
    memset(socks->parsers->connect_parser, 0x00, sizeof(*(socks->parsers->connect_parser)));
    memset(socks->parsers->auth_parser, 0x00, sizeof(*(socks->parsers->auth_parser)));
    memset(socks->parsers->req_parser, 0x00, sizeof(*(socks->parsers->req_parser)));

    socks->stm.initial = HELLO_READ;
    socks->stm.max_state = DONE;
    socks->stm.states = states;
    stm_init(&socks->stm);

    socks->buffers = malloc(sizeof(struct buffers_t));
    socks->buffers->aux_read_buff = malloc((uint32_t)BUFF_SIZE);
    socks->buffers->aux_write_buff = malloc((uint32_t)BUFF_SIZE);

    buffer_init(&socks->buffers->read_buff, BUFF_SIZE, socks->buffers->aux_read_buff);
    buffer_init(&socks->buffers->write_buff, BUFF_SIZE, socks->buffers->aux_write_buff);

    return socks;
}

