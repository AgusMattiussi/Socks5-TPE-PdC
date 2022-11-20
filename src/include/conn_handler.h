#ifndef CONN_HANDLER_H
#define CONN_HANDLER_H

#include "stm.h"
#include "../socks5/socks5.h"
#include "../mng/mng.h"
#include "selector.h"
#include "../logger/logger.h"
#include "../include/server.h"

/*
            CONN_HANDLER.h
Implements handlers for socks incoming connections
*/


void socks_connection_read(struct selector_key * key);
void socks_connection_write(struct selector_key * key);
void socks_connection_block(struct selector_key * key);
void socks_connection_close(struct selector_key * key);

void mng_connection_read(struct selector_key * key);
void mng_connection_write(struct selector_key * key);
void mng_connection_block(struct selector_key * key);
void mng_connection_close(struct selector_key * key);

#endif