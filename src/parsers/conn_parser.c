#include "conn_parser.h"
#include "../buffer/buffer.h"
#include "../selector/selector.h"
#include "../conn_handler.h"

#include <stdio.h>

bool check_if_valid_method(uint8_t byte){
    return byte == NO_AUTH || byte == USER_PASS;
}

void start_connection_parser(struct conn_parser * parser){
    parser->to_parse = 0;
    parser->state = CONN_VERSION; // Start of msg
    parser->auth = NO_METHODS;
    parser->buff = NULL;
}

void conn_parse_byte(struct conn_parser * parser, uint8_t to_parse){
    switch(to_parse){
        //What state are we in, and what does this byte mean in that context
        case CONN_VERSION:
            if(to_parse == SOCKS_VERSION){
                parser->state = CONN_NMETHODS;
                break;
            }
            else{
                parser->state = CONN_ERROR;
                fprintf(STDOUT_FILENO, "Invalid socks version.");
                break;
            }
        case CONN_NMETHODS:
            //TODO: Re hacer este método (no va a andar si no)
            if(to_parse == 0x00){

            }
            parser->state = to_parse == 0? CONN_DONE:CONN_METHODS;
            break;
        case CONN_METHODS:
            if(to_parse != GSSAPI){
                bool valid_method = check_if_valid_method(to_parse);
                if(valid_method){
                    parser->auth = (enum auth_method) to_parse;
                }
                else{
                    fprintf(STDOUT_FILENO, "Invalid auth method provided.");
                    parser->state = CONN_ERROR;
                }
            }
            else{
                fprintf(STDOUT_FILENO, "Current project version does not support auth via GSS_API yet. Sorry.");
                parser->state = CONN_ERROR;
            }
            break;
        case CONN_DONE: case CONN_ERROR: break;
        default: fprintf(stdout, "Error at parsing. Please try again.");
    }
}

enum conn_state conn_parse_full(struct conn_parser * parser, buffer * buff){
    // Take byte to byte and use helper function to pass between states
    // We can use buffer functions directly to know when to stop reading
    while(buffer_can_read(buff)){
        uint8_t to_parse = buffer_read(buff);
        conn_parse_byte(parser, to_parse);
        if(parser->state == CONN_ERROR){
            fprintf(stdout, "Error while parsing input."); //Might be excesive
            return CONN_ERROR;
        }
        else if(parser->state == CONN_DONE){
            //For debugging purposes
            fprintf(stdout, "Connection OK!");
            return CONN_DONE;
        }
    }
    if(parser->state != CONN_ERROR && parser->state != CONN_DONE){
        //For debugging purposes
        fprintf(stdout, "Shouldn't reach this state, but parsing went wrong with no aparent error?");
    }
    return parser->state;
}