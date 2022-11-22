#include "auth_parser.h"
#include "../logger/logger.h"

void auth_parser_init(struct auth_parser * parser){
    parser->state = AUTH_VER;
    parser->to_parse = 0;
    parser->where_to = NULL;
}

void plain_parse_byte(struct auth_parser * parser, uint8_t to_parse){
    *parser->where_to = to_parse;
    parser->to_parse--; parser->where_to++;
    if(parser->to_parse == 0){
        parser->state = parser->state == AUTH_UNAME?AUTH_PLEN:AUTH_DONE;
        parser->where_to = NULL; 
    }
}

void set_len_to_parse(struct auth_parser * parser, uint8_t to_parse){
    enum auth_state current = parser->state;
    if(to_parse != 0){
        parser->to_parse = to_parse;
        parser->state = current == AUTH_ULEN ? AUTH_UNAME : AUTH_PASSWD;
        parser->where_to = current == AUTH_ULEN ? parser->username : parser->password;
        parser->where_to[to_parse]='\0'; //Delimiting end of string dynamically.
        return;
    }
    if(current == AUTH_ULEN) parser->state = AUTH_PLEN;
    else{ /*Can only be PLEN*/ parser->state = AUTH_DONE;}
}

void auth_parse_byte(struct auth_parser * parser, uint8_t to_parse){
    switch(parser->state){
        case AUTH_VER:
            LogDebug("[AUTH_VER] parsing byte %d\n", to_parse); 
            if(to_parse == AUTH_VERSION){parser->state = AUTH_ULEN;}
            else{parser->state = AUTH_ERROR;}
            break;
        case AUTH_ULEN:
        case AUTH_PLEN:
            LogDebug("[AUTH_(U|P)LEN] parsing byte %d\n", to_parse);         
            set_len_to_parse(parser, to_parse);
            break;
        case AUTH_UNAME:
        case AUTH_PASSWD:
            LogDebug("[AUTH_UNAME/PASSWD] parsing byte %c\n", to_parse);         
            plain_parse_byte(parser, to_parse);
            break;
        case AUTH_DONE:
        case AUTH_ERROR:
            LogDebug("[AUTH_DONE/ERROR] parsing byte %d\n", to_parse);         
            break;
        default:
            LogError("Should never reach this state.");
            break;
    }
}


enum auth_state auth_parse_full(struct auth_parser * parser, buffer * buff){
    while(buffer_can_read(buff)){
        uint8_t byte = buffer_read(buff);
        auth_parse_byte(parser, byte);
        if(parser->state == AUTH_ERROR){
            LogDebug("Authentication failed");
            return AUTH_ERROR;
        }
        else if(parser->state == AUTH_DONE){
            LogDebug("Auth OK!");
            return AUTH_DONE;
        }
    }
    if(parser->state != AUTH_ERROR && parser->state != AUTH_DONE){
        //For debugging purposes
        LogError("Shouldn't reach this state, but parsing went wrong with no aparent error?");
    }
    return parser->state;
}