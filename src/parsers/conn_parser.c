#include "conn_parser.h"

bool 
check_if_valid_method(uint8_t byte){
    return byte == NO_AUTH || byte == USER_PASS;
}

void 
start_connection_parser(struct conn_parser * parser){
    parser->to_parse = 0;
    parser->state = CONN_VERSION;
    parser->auth = NO_METHODS;
    parser->buff = NULL;
}

void 
set_new_method(struct conn_parser * parser, enum auth_method to_parse){
    if(to_parse == USER_PASS || 
    (!needs_auth() && to_parse == NO_AUTH && parser->auth != USER_PASS)){
        parser->auth = to_parse;
    }
}

void 
conn_parse_byte(struct conn_parser * parser, uint8_t to_parse){
    switch(parser->state){
        case CONN_VERSION:
            LogDebug("[CONN_VERSION] Value of byte to parse: %d\n", to_parse);
            if(to_parse == SOCKS_VERSION){
                parser->state = CONN_NMETHODS;
                break;
            }
            else{
                parser->state = CONN_ERROR;
                LogDebug("Invalid socks version.\n");
                break;
            }
        case CONN_NMETHODS:
            LogDebug("[CONN_NMETHODS] Value of byte to parse: %d\n", to_parse);
            if(to_parse == 0x00){
                parser->state = CONN_DONE;
            }
            else{
                parser->to_parse = to_parse;
                parser->state = CONN_METHODS;
            }
            break;
        case CONN_METHODS:
            LogDebug("[CONN_METHODS] Value of byte to parse: %d\n", to_parse);
            set_new_method(parser, to_parse);
            parser->to_parse--;
            if(parser->to_parse==0) parser->state = CONN_DONE;
            break;
        case CONN_DONE: case CONN_ERROR: break;
        default: LogError("Error at parsing. Please try again.\n"); 
    }
}

enum conn_state 
conn_parse_full(struct conn_parser * parser, buffer * buff){
    while(buffer_can_read(buff)){
        uint8_t to_parse = buffer_read(buff);
        conn_parse_byte(parser, to_parse);
        if(parser->state == CONN_ERROR){
            LogError("Error while parsing input.\n");
            return CONN_ERROR;
        }
        else if(parser->state == CONN_DONE){
            LogDebug("Connection OK!\n");
            return CONN_DONE;
        }
    }
    if(parser->state != CONN_ERROR && parser->state != CONN_DONE){
        LogError("Shouldn't reach this state, but parsing went wrong with no aparent error?\n");
    }
    return parser->state;
}