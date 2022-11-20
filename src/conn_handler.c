#include "include/conn_handler.h"

void socks_connection_read(struct selector_key * key){
    //Recupero información y le paso al handler de lectura de stm
    LogDebug("Entering socks_connection_read");
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_read(&connection->stm, key);
    if(state == ERROR){
        //For debugging purposes
        LogError("Error in stm read");
        close_socks_conn(connection);
    }
    else if(state == DONE){
        //For debugging purposes
        LogDebug("STM is DONE");
        close_socks_conn(connection);
    }
}

void socks_connection_write(struct selector_key * key){
    LogDebug("Entro a socks connection write\n");
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_write(&connection->stm, key);
    if(state == ERROR){
        LogError("Error in stm writing");
        close_socks_conn(connection);
    }
    else if(state == DONE){
        LogDebug("STM is DONE");
        close_socks_conn(connection);
    }
}

void socks_connection_block(struct selector_key * key){
    LogDebug("Entro a socks connection block\n");
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_block(&connection->stm, key);
    if(state == ERROR){
        LogError("Error in stm writing");
        close_socks_conn(connection);
    }
    else if(state == DONE){
        LogDebug("STM is DONE");
        close_socks_conn(connection);
    }
}

void socks_connection_close(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    close_socks_conn(connection);
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