#include "conn_handler.h"
#include "stm/stm.h"
#include "socks5/socks5.h"

void close(socks_conn_model * connection){}


void socks_connection_read(struct selector_key * key){
    //Recupero información y le paso al handler de lectura de stm
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_read(&connection->stm, key);
    if(state == ERROR){
        //For debugging purposes
        fprintf(STDOUT_FILENO, "Error in stm reading");
        close(connection);
    }
    else if(state == DONE){
        //For debugging purposes
        fprintf(STDOUT_FILENO, "STM is DONE");
        close(connection);
    }
}
void socks_connection_write(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_write(&connection->stm, key);
    if(state == ERROR){
        fprintf(STDOUT_FILENO, "Error in stm writing");
        close(connection);
    }
    else if(state == DONE){
        fprintf(STDOUT_FILENO, "STM is DONE");
        close(connection);
    }
}
void socks_connection_block(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_block(&connection->stm, key);
    if(state == ERROR){
        fprintf(STDOUT_FILENO, "Error in stm writing");
        close(connection);
    }
    else if(state == DONE){
        fprintf(STDOUT_FILENO, "STM is DONE");
        close(connection);
    }
}
void socks_connection_close(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    close(connection);
}