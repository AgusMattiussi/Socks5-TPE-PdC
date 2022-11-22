#include "include/conn_handler.h"

void check_state(socks_conn_model * socks, enum socks_state state) {
    if(state == ERROR){
        LogError("Error in stm writing");
        close_socks_conn(socks);
    }
    else if(state == DONE){
        LogDebug("STM is DONE");
        close_socks_conn(socks);
    }
}

void socks_conn_read(struct selector_key * key){
    LogDebug("Entering socks_conn_read");
    socks_conn_model * socks = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_read(&socks->stm, key);
    check_state(socks, state);
}

void socks_conn_write(struct selector_key * key){
    LogDebug("Entro a socks conn write\n");
    socks_conn_model * socks = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_write(&socks->stm, key);
    check_state(socks, state);
}

void socks_conn_block(struct selector_key * key){
    LogDebug("Entro a socks conn block\n");
    socks_conn_model * socks = (socks_conn_model *) key->data;
    enum socks_state state = stm_handler_block(&socks->stm, key);
    check_state(socks, state);
}

void socks_conn_close(struct selector_key * key){
    LogDebug("Entro a socks conn close\n");
    socks_conn_model * socks = (socks_conn_model *) key->data;
    close_socks_conn(socks);
}
