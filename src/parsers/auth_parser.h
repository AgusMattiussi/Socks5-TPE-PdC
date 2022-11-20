#ifndef AUTH_PARSER_H
#define AUTH_PARSER_H

#include "../include/buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define AUTH_VERSION 0x01
#define MAX_LEN 255

enum auth_state{
    AUTH_VER,
    AUTH_ULEN,
    AUTH_UNAME,
    AUTH_PLEN,
    AUTH_PASSWD,
    AUTH_DONE,
    AUTH_ERROR,
};

struct auth_parser{
    enum auth_state state;
    uint8_t to_parse;
    uint8_t * where_to;
    uint8_t username[MAX_LEN];
    uint8_t password[MAX_LEN];
};

void auth_parser_init(struct auth_parser * parser);
enum auth_state auth_parse_full(struct auth_parser * parser, buffer * buff);
enum auth_state mng_auth_parse_full(struct auth_parser * parser, buffer * buff);

#endif