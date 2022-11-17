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
    printf("Entro a socks connection read\n");
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_read(&connection->stm, key);
    if(state == ERROR){
        //For debugging purposes
        printf("Error in stm read\n");
        close_socks5_connection(connection);
    }
    else if(state == DONE){
        //For debugging purposes
        printf("STM is DONE\n");
        close_socks5_connection(connection);
    }
}
void socks_connection_write(struct selector_key * key){
    printf("Entro a socks connection write\n");
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_write(&connection->stm, key);
    if(state == ERROR){
        fprintf(stdout, "Error in stm writing\n");
        close_socks5_connection(connection);
    }
    else if(state == DONE){
        fprintf(stdout, "STM is DONE\n");
        close_socks5_connection(connection);
    }
}

void socks_connection_block(struct selector_key * key){
    printf("Entro a socks connection block\n");
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_block(&connection->stm, key);
    if(state == ERROR){
        fprintf(stdout, "Error in stm writing\n");
        close_socks5_connection(connection);
    }
    else if(state == DONE){
        fprintf(stdout, "STM is DONE\n");
        close_socks5_connection(connection);
    }
}
void socks_connection_close(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    close_socks5_connection(connection);
}

void mng_connection_read(struct selector_key * key){
    //Recupero información y le paso al handler de lectura de stm
    printf("Entro a mng connection read\n");
    mng_conn_model * connection = (mng_conn_model *) key->data;
    enum mng_state state = stm_handler_read(&connection->stm, key);
    if(state == MNG_ERROR){
        //For debugging purposes
        printf("Error in stm read\n");
        close_socks5_connection(connection);
    }
    else if(state == MNG_DONE){
        //For debugging purposes
        printf("STM is DONE\n");
        close_socks5_connection(connection);
    }
}

void mng_connection_write(struct selector_key * key){
    printf("Entro a mng connection write\n");
    mng_conn_model * connection = (mng_conn_model *) key->data;
    enum mng_state state = stm_handler_write(&connection->stm, key);
    if(state == MNG_ERROR){
        fprintf(stdout, "Error in stm writing\n");
        close_socks5_connection(connection);
    }
    else if(state == MNG_DONE){
        fprintf(stdout, "STM is DONE\n");
        close_socks5_connection(connection);
    }
}

void mng_connection_block(struct selector_key * key){
    printf("Entro a socks connection block\n");
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_block(&connection->stm, key);
    if(state == MNG_ERROR){
        fprintf(stdout, "Error in stm writing\n");
        close_socks5_connection(connection);
    }
    else if(state == MNG_DONE){
        fprintf(stdout, "STM is DONE\n");
        close_socks5_connection(connection);
    }
}
void mng_connection_close(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    close_socks5_connection(connection);
}