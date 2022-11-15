#include "include/conn_handler.h"


void close_socks5_connection(socks_conn_model * connection){
    if(connection->cli_conn->socket != -1){
        //TODO: Creo que hay que sacar el FD del selector acá
        close(connection->cli_conn->socket);
    }
    if(connection->src_conn->socket != -1){close(connection->src_conn->socket);}
    if(connection->resolved_addr != NULL){freeaddrinfo(connection->resolved_addr);}
    buffer_reset(&connection->buffers->read_buff);
    buffer_reset(&connection->buffers->write_buff);
    free(connection->buffers->aux_read_buff);
    free(connection->buffers->aux_write_buff);
    free(connection);
}

void socks_connection_read(struct selector_key * key){
    //Recupero información y le paso al handler de lectura de stm
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_read(&connection->stm, key);
    if(state == ERROR){
        //For debugging purposes
        fprintf(stdout, "Error in stm read");
        close_socks5_connection(connection);
    }
    else if(state == DONE){
        //For debugging purposes
        fprintf(stdout, "STM is DONE");
        close_socks5_connection(connection);
    }
}
void socks_connection_write(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_write(&connection->stm, key);
    if(state == ERROR){
        fprintf(stdout, "Error in stm writing");
        close_socks5_connection(connection);
    }
    else if(state == DONE){
        fprintf(stdout, "STM is DONE");
        close_socks5_connection(connection);
    }
}

void socks_connection_block(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_block(&connection->stm, key);
    if(state == ERROR){
        fprintf(stdout, "Error in stm writing");
        close_socks5_connection(connection);
    }
    else if(state == DONE){
        fprintf(stdout, "STM is DONE");
        close_socks5_connection(connection);
    }
}
void socks_connection_close(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    close_socks5_connection(connection);
}