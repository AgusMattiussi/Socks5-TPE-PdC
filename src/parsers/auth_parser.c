#include "auth_parser.h"

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
    if(to_parse == 0){
        if(current == AUTH_ULEN) parser->state = AUTH_PLEN;
        else{ /*Can only be PLEN*/ parser->state = AUTH_DONE;}
    }
    else{
        parser->to_parse = to_parse;
        parser->state = current == AUTH_ULEN ? AUTH_UNAME : AUTH_PASSWD;
        parser->where_to = current == AUTH_ULEN ? parser->username : parser->password;
        parser->where_to[to_parse]='\0'; //Delimiting end of string dynamically.
    }
}

void auth_parse_byte(struct auth_parser * parser, uint8_t to_parse){
    switch(parser->state){
        case AUTH_VER:
            printf("[AUTH_VER] parseo byte %d", to_parse); 
            if(to_parse == AUTH_VERSION){parser->state = AUTH_ULEN;}
            else{parser->state = AUTH_ERROR;}
            break;
        case AUTH_ULEN:
        case AUTH_PLEN:
            printf("[AUTH_(U|P)LEN] parseo byte %d", to_parse);         
            set_len_to_parse(parser, to_parse);
            break;
        case AUTH_UNAME:
        case AUTH_PASSWD:
            printf("[AUTH_UNAME/PASSWD] parseo byte %d", to_parse);         
            plain_parse_byte(parser, to_parse);
            break;
        case AUTH_DONE:
        case AUTH_ERROR:
            printf("[AUTH_DONE/ERROR] parseo byte %d", to_parse);         
            break;
        default:
            fprintf(stdout, "Should never reach this state.");
            break;
    }
}


enum auth_state auth_parse_full(struct auth_parser * parser, buffer * buff){
    printf("Entro a parsear bytes de request\n");
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