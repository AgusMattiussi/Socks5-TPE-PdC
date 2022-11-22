#ifndef POP3_SNIFFER_H
#define POP3_SNIFFER_H

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "../include/buffer.h"

/*
Esquema POP3 (RFC 1939)
Abrimos conexion TCP en el puerto 110 -> greeting -> auth (user + pass) -> transaction (requests al server pop3) -> quit

Greeting:
    S:  +OK POP3 server ready

Auth:
    -USER name
        Possible Responses:
             +OK name is a valid mailbox
             -ERR never heard of mailbox name

         Examples:
             C: USER frated
             S: -ERR sorry, no mailbox for frated here
                ...
             C: USER mrose
             S: +OK mrose is a real hoopy frood

    -PASS string
        Possible Responses:
             +OK maildrop locked and ready
             -ERR invalid password
             -ERR unable to lock maildrop

         Examples:
             C: USER mrose
             S: +OK mrose is a real hoopy frood
             C: PASS secret
             S: -ERR maildrop already locked
               ...
             C: USER mrose
             S: +OK mrose is a real hoopy frood
             C: PASS secret
             S: +OK mrose's maildrop has 2 messages (320 octets)
*/

/*
RFC 2449
The maximum length of a command is increased from 47 characters (4
character command, single space, 40 character argument, CRLF) to 255
octets, including the terminating CRLF.
*/

#define ARGUMENT_LENGTH 40

#define POP3_PORT 110

typedef enum pop3_state {
    POP3_USER_CMD,
    POP3_USER,
    POP3_PASS_CMD,
    POP3_PASS,
    POP3_ERROR,
    POP3_DONE
} pop3_state;

typedef struct node {
    char * username;
    char * password;
    struct node * next;
} node;

typedef struct users_list {
    node * first;
    int size;
} users_list;

typedef struct pop3_parser {
    pop3_state state;
    buffer buff;
    uint8_t user[ARGUMENT_LENGTH];
    uint8_t pass[ARGUMENT_LENGTH];
    uint16_t read_ptr;
    uint16_t write_ptr;
    bool user_done;
} pop3_parser;

users_list * init_users_list();

void free_list(users_list * list);

users_list * get_sniffed_users();

void pop3_parser_init(pop3_parser * parser);

pop3_state pop3_parse(pop3_parser * parser, buffer * buff);

bool sniffer_is_on();

void set_sniffer_state(bool newState);

int add_node(users_list * list, uint8_t * username, uint8_t * password);
#endif