#include "include/conn_handler.h"
#include "logger/logger.h"
#include "include/server.h"

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
        LogError("STM is DONE");
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
        LogError("STM is DONE");
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
        LogInfo("STM is DONE");
        close_socks_conn(connection);
    }
}

void socks_connection_close(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    close_socks_conn(connection);
}