#include "include/conn_handler.h"

void socks_connection_read(struct selector_key * key){
    //Recupero información y le paso al handler de lectura de stm
    printf("Entro a socks connection read\n");
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_read(&connection->stm, key);
    if(state == ERROR){
        //For debugging purposes
        printf("Error in stm read\n");
        close_socks_conn(connection);
    }
    else if(state == DONE){
        //For debugging purposes
        printf("STM is DONE\n");
        close_socks_conn(connection);
    }
}

void socks_connection_write(struct selector_key * key){
    printf("Entro a socks connection write\n");
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_write(&connection->stm, key);
    if(state == ERROR){
        fprintf(stdout, "Error in stm writing\n");
        close_socks_conn(connection);
    }
    else if(state == DONE){
        fprintf(stdout, "STM is DONE\n");
        close_socks_conn(connection);
    }
}

void socks_connection_block(struct selector_key * key){
    printf("Entro a socks connection block\n");
    socks_conn_model * connection = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_block(&connection->stm, key);
    if(state == ERROR){
        fprintf(stdout, "Error in stm writing\n");
        close_socks_conn(connection);
    }
    else if(state == DONE){
        fprintf(stdout, "STM is DONE\n");
        close_socks_conn(connection);
    }
}

void socks_connection_close(struct selector_key * key){
    socks_conn_model * connection = (socks_conn_model *) key->data;
    close_socks_conn(connection);
}