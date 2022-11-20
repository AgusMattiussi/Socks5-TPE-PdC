#ifndef CONN_PARSER_H
#define CONN_PARSER_H

#include <stdint.h>
#include <stdio.h>

#include "../include/buffer.h"
#include "../include/selector.h"
#include "../include/conn_handler.h"
#include "../logger/logger.h"
#include "../users/user_mgmt.h"

const static uint8_t SOCKS_VERSION = 0x05;

enum auth_method{
    NO_AUTH = 0x00,
    GSSAPI = 0x01,
    USER_PASS = 0x02,
    NO_METHODS = 0xFF,
};

enum conn_state{
    CONN_VERSION, 
    CONN_NMETHODS,
    CONN_METHODS,
    CONN_DONE,
    CONN_ERROR,
};

struct conn_parser {
    uint8_t auth;
    enum conn_state state;
    int to_parse;
    char * buff;
};

void start_connection_parser(struct conn_parser * parser);
void conn_parse_byte(struct conn_parser * parser, uint8_t to_parse);
enum conn_state conn_parse_full(struct conn_parser * parser, buffer * buff);
enum conn_state mng_conn_parse_full(struct conn_parser * parser, buffer * buff);

#endif