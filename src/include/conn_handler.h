#ifndef CONN_HANDLER_H
#define CONN_HANDLER_H

#include "stm.h"
#include "../socks5/socks5.h"
#include "selector.h"
#include "../logger/logger.h"
#include "../include/server.h"

/*
            CONN_HANDLER.h
Implements handlers for socks incoming connections
*/


void socks_conn_read(struct selector_key * key);
void socks_conn_write(struct selector_key * key);
void socks_conn_block(struct selector_key * key);
void socks_conn_close(struct selector_key * key);

void mng_conn_read(struct selector_key * key);
void mng_conn_write(struct selector_key * key);
void mng_conn_block(struct selector_key * key);
void mng_conn_close(struct selector_key * key);

#endif