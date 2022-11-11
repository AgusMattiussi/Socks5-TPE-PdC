#include "auth_parser.h"
#include "../buffer/buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void auth_parser_init(struct auth_parser * parser){
    parser->state = AUTH_VER;
    parser->to_parse = 0;
    //TODO
}

void set_len_to_parse(struct auth_parser * parser, uint8_t byte){
    enum auth_state current = parser->state;
    if(byte == 0){
        if(current == AUTH_ULEN) parser->state = AUTH_PLEN;
        else{ /*Can only be PLEN*/ parser->state = AUTH_DONE;}
    }
    else{
        parser->to_parse = byte;
        parser->state = current == AUTH_ULEN?AUTH_UNAME:AUTH_PASSWD;
        parser->where_to = current == AUTH_ULEN?parser->username:parser->password;

    }
}

void auth_parse_byte(struct auth_parser * parser, uint8_t byte){
    switch(byte){
        case AUTH_VER: 
            if(byte == AUTH_VERSION){parser->state = AUTH_ULEN;}
            else{parser->state = AUTH_ERROR;}
            break;
        case AUTH_ULEN:
        case AUTH_PLEN:
            set_len_to_parse(parser, byte);
            break;
        case AUTH_UNAME:
        case AUTH_PASSWD:
            plain_parse_byte(parser, byte);
            break;
        case AUTH_DONE:
        case AUTH_ERROR:
            break;
        default:
            fprintf(stdout, "Should never reach this state.");
            break;
    }
}


enum auth_state auth_parse_full(struct auth_parser * parser, buffer * buff){
    while(buffer_can_read(buff)){
        uint8_t byte = buffer_read(buff);
        auth_parse_byte(parser, byte);
        if(parser->state == AUTH_ERROR){
            fprintf(stdout, "Authentication failed");
            return AUTH_ERROR;
        }
        else if(parser->state == AUTH_DONE){
            fprintf(stdout, "Auth OK!");
            return AUTH_DONE;
        }
    }
    if(parser->state != AUTH_ERROR && parser->state != AUTH_DONE){
        //For debugging purposes
        fprintf(stdout, "Shouldn't reach this state, but parsing went wrong with no aparent error?");
    }
    return parser->state;
}