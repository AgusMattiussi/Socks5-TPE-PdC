#include "mng.h"

void mng_conn_read_init(const unsigned state, struct selector_key * key){
    mng_conn_model * connection = (mng_conn_model *)key->data;
    printf("Llego a mng_hello_read_init\n");
    start_connection_parser(connection->parsers->connect_parser);
 }

 static enum mng_state
 mng_conn_read(struct selector_key * key){
    printf("Llego a mng_hello_read\n");
    
    mng_conn_model * connection = (mng_conn_model *)key->data;
    struct conn_parser * parser = connection->parsers->connect_parser;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_write_ptr(&connection->buffers->read_buff, &byte_n);
    ssize_t n_received = recv(connection->cli_conn->socket, buff_ptr, byte_n, 0); //TODO:Flags?

    if(n_received <= 0) return MNG_ERROR;
    buffer_write_adv(&connection->buffers->read_buff, n_received);

    enum conn_state ret_state = mng_conn_parse_full(parser, &connection->buffers->read_buff);
    if(ret_state == CONN_ERROR){
        fprintf(stderr, "Error while parsing.");
        return MNG_ERROR;
    }
    if(ret_state == CONN_DONE){
        // Nothing else to read, we move to writing
        selector_status ret_selector = selector_set_interest_key(key, OP_WRITE);
        //If finished, we need to create and send the srv response
        if(ret_selector == SELECTOR_SUCCESS){
            size_t n_available;
            //TODO: específico a nuestro protocolo
            uint8_t * write_ptr = buffer_write_ptr(&connection->buffers->write_buff, &n_available);
            if(n_available < 2){
                fprintf(stdout, "Not enough space to send connection response.");
                return MNG_ERROR;
            }
            write_ptr[0] = SOCKS_VERSION; write_ptr[1] = parser->auth;
            buffer_write_adv(&connection->buffers->write_buff, 2);
            
            printf("todo ok\n");
            return MNG_CONN_WRITE;
        }
        return MNG_ERROR;
    }
    return MNG_CONN_READ;
 }

 static enum mng_state
mng_conn_write(struct selector_key * key){
    
    mng_conn_model * connection = (mng_conn_model *) key->data;
    // We need to build the write the server response to buffer
    size_t n_available;
    uint8_t * buff_ptr = buffer_read_ptr(&connection->buffers->write_buff, &n_available);
    ssize_t n_sent = send(connection->cli_conn->socket, buff_ptr, n_available, 0); //TODO: Flags?
    if(n_sent == -1){
        fprintf(stdout, "Error sending bytes to client socket.");
        return MNG_ERROR;
    }
    printf("Mande %d bytes hacia cli\n", n_sent);
    buffer_read_adv(&connection->buffers->write_buff, n_sent);
    // We need to check whether there is something else to send. If so, we keep writing
    if(buffer_can_read(&connection->buffers->write_buff)){
        return MNG_CONN_WRITE;
    }
    // Nothing else to send. We set fd_interests and add to selector
    selector_status status = selector_set_interest_key(key, OP_READ);
    if(status != SELECTOR_SUCCESS) return MNG_ERROR;
    return MNG_AUTH_READ;
    /*switch(connection->parsers->connect_parser->auth){
        case NO_AUTH:
            printf("STM pasa a estado REQ_READ\n");
            return REQ_READ;
        case USER_PASS:
            printf("STM pasa a estado AUTH_READ\n");
            return MNG_AUTH_READ;
        case GSSAPI:
            fprintf(stdout, "GSSAPI is out of this project's scope.");
            return DONE;
        case NO_METHODS:
            return DONE;
    }
    return ERROR;*/
}

void mng_auth_read_init(const unsigned state, struct selector_key * key){
    mng_conn_model * connection = (mng_conn_model *)key->data;
    printf("Llego a mng_auth_read_init\n");
    auth_parser_init(connection->parsers->auth_parser);
 }

 static enum mng_state 
 mng_auth_read(struct selector_key * key){
    printf("Llego a mng_auth_read\n");

    mng_conn_model * connection = (mng_conn_model *)key->data;
    struct auth_parser * parser = connection->parsers->auth_parser;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_write_ptr(&connection->buffers->read_buff, &byte_n);
    ssize_t n_received = recv(connection->cli_conn->socket, buff_ptr, byte_n, 0); //TODO: Flags?
    if(n_received <= 0) return MNG_ERROR;
    buffer_write_adv(&connection->buffers->read_buff, n_received);

    enum auth_state ret_state = mng_auth_parse_full(parser, &connection->buffers->read_buff);
    if(ret_state == AUTH_ERROR){
        fprintf(stdout, "Error parsing auth method");
        return MNG_ERROR;
    }
    if(ret_state == AUTH_DONE){ 
        //TODO: Build process_authentication_request (declared, not built yet)
        /*
        uint8_t is_authenticated = process_authentication_request((char*)parser->username, 
                                                                  (char*)parser->password);
        */
        selector_status ret_selector = selector_set_interest_key(key, OP_WRITE);
        if(ret_selector != SELECTOR_SUCCESS) return MNG_ERROR;
        
        
        //TODO: Maybe move to auth_write method?
        size_t n_available;
        uint8_t * write_ptr = buffer_write_ptr(&connection->buffers->write_buff, &n_available);
        if(n_available < 2){
            fprintf(stdout, "Not enough space to send connection response.");
            return MNG_ERROR;
        }
        write_ptr[0] = AUTH_VERSION;
        //write_ptr[1] = is_authenticated;
        //buffer_write_adv(&connection->buffers->write_buff, 2);
        buffer_write_adv(&connection->buffers->write_buff, 1);
        return MNG_AUTH_WRITE;
    }
    return MNG_AUTH_READ;
 }

 static enum mng_state
 mng_auth_write(struct selector_key * key){
    printf("estoy en mng_auth_write\n");
    mng_conn_model * connection = (mng_conn_model *)key->data;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_read_ptr(&connection->buffers->write_buff, &byte_n);
    ssize_t n_sent = send(connection->cli_conn->socket, buff_ptr, byte_n, 0); //TODO: Flags?
    if(n_sent <= 0) return MNG_ERROR;
    buffer_read_adv(&connection->buffers->write_buff, n_sent);
    if(buffer_can_read(&connection->buffers->write_buff)){
        return MNG_AUTH_WRITE;
    }
    selector_status ret_selector = selector_set_interest_key(key, OP_READ);
    return ret_selector == SELECTOR_SUCCESS? MNG_REQ_READ:MNG_ERROR;
 }

 void mng_req_read_init(const unsigned state, struct selector_key * key){
    mng_conn_model * connection = (mng_conn_model *)key->data;
    printf("Llego a mng_req_read_init\n");
    req_parser_init(connection->parsers->req_parser);
 }

 static enum mng_state
 mng_req_read(struct selector_key * key){
     printf("Llego a mng_req_read\n");

    mng_conn_model * connection = (mng_conn_model *)key->data;
    struct req_parser * parser = connection->parsers->req_parser;

    size_t byte_n;
    uint8_t * buff_ptr = buffer_write_ptr(&connection->buffers->read_buff, &byte_n);
    ssize_t n_received = recv(connection->cli_conn->socket, buff_ptr, byte_n, 0); //TODO: Flags?
    if(n_received <= 0) return MNG_ERROR;
    buffer_write_adv(&connection->buffers->read_buff, n_received);

    enum req_state ret_state = mng_req_parse_full(parser, &connection->buffers->read_buff);
    if(ret_state == REQ_ERROR){
        fprintf(stdout, "Error parsing req method");
        return MNG_ERROR;
    }
    if(ret_state == REQ_DONE){ 
        selector_status ret_selector = selector_set_interest_key(key, OP_WRITE);
        if(ret_selector != SELECTOR_SUCCESS) return MNG_ERROR;
        //TODO: qué le devuelvo al cliente?
        return MNG_REQ_WRITE;
    }
    //sacar esta línea
    return MNG_REQ_READ;
 }

 static enum mng_state
 mng_req_write(struct selector_key * key){
    printf("estoy en mng_req_write\n");
    mng_conn_model * connection = (mng_conn_model *)key->data;
    
    size_t byte_n;
    uint8_t * buff_ptr = buffer_read_ptr(&connection->buffers->write_buff, &byte_n);
    ssize_t n_sent = send(connection->cli_conn->socket, buff_ptr, byte_n, 0); //TODO: Flags?
    if(n_sent <= 0) return ERROR;
    buffer_read_adv(&connection->buffers->write_buff, n_sent);
    if(buffer_can_read(&connection->buffers->write_buff)){
        return MNG_REQ_WRITE;
    }
    selector_status ret_selector = selector_set_interest_key(key, OP_READ);
    return ret_selector == SELECTOR_SUCCESS? MNG_REQ_READ:MNG_ERROR;
 }

static const struct state_definition states[] = {
    {
        .state = MNG_CONN_READ,
        .on_arrival = mng_conn_read_init,
        .on_read_ready = mng_conn_read,
    },
    {
        .state = MNG_CONN_WRITE,
        .on_write_ready = mng_conn_write,
    },
    {
        .state = MNG_AUTH_READ,
        .on_arrival = mng_auth_read_init,
        .on_read_ready = mng_auth_read,
    },
    {
        .state = MNG_AUTH_WRITE,
        .on_write_ready = mng_auth_write,
    },
    {
        .state = MNG_REQ_READ,
        .on_arrival = mng_req_read_init,
        .on_read_ready = mng_req_read,
    },
    {
        .state = MNG_REQ_WRITE,
        .on_write_ready = mng_req_write,
    },
    {
        .state = MNG_ERROR,
    },
    {
        .state = MNG_DONE,
    }
};

 struct state_definition * mng_all_states() {
    return states;
}