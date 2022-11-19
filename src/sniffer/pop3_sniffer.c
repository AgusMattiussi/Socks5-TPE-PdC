#include "pop3_sniffer.h"

static bool sniffer_state = true;
static const char * pop3_user_cmd = "USER ";
static const char * pop3_pass_cmd = "PASS ";


static pop3_state parse_user_cmd(pop3_parser * parser, uint8_t c){
    if(toupper(c) == pop3_user_cmd[parser->read_ptr]){
        parser->read_ptr++;
        if(pop3_user_cmd[parser->read_ptr] == '\0') { // Lei "USER " en el buffer -> ahora me lo tengo que guardar
            parser->read_ptr = 0; // reinicio el ptr de lectura
            return POP3_USER;
        }
        // tengo que seguir parseando el comando para ver si es "USER "
        return POP3_USER_CMD;
    }
    return POP3_ERROR;
}

static pop3_state parse_user(pop3_parser * parser, uint8_t c){
    if(parser->write_ptr + 1 == ARGUMENT_LENGTH)
        return POP3_ERROR;

    if(c == '\n'){
        parser->user[parser->write_ptr++] = '\0';
        parser->write_ptr = 0;
        return POP3_PASS_CMD;
    }

    parser->user[parser->write_ptr++] = (char) c;
    return POP3_USER;
}

static pop3_state parse_pass_cmd(pop3_parser * parser, uint8_t c){
    if(toupper(c) == pop3_pass_cmd[parser->read_ptr]){
        parser->read_ptr++;
        if(pop3_pass_cmd[parser->read_ptr] == '\0') {
            parser->read_ptr = 0; 
            return POP3_PASS;
        }
        return POP3_PASS_CMD;
    }
    return POP3_ERROR;
}

static pop3_state parse_pass(pop3_parser * parser, uint8_t c){
    if(parser->write_ptr + 1 == ARGUMENT_LENGTH)
        return POP3_ERROR;

    if(c == '\n'){
        parser->pass[parser->write_ptr++] = '\0';
        parser->write_ptr = 0;
        return POP3_DONE;
    }

    parser->pass[parser->write_ptr++] = (char) c;
    return POP3_PASS;
}

static void pop3_parse_byte(pop3_parser * parser){
    while(buffer_can_read(&parser->buff) && parser->state != POP3_DONE){
        
        uint8_t c = buffer_read(&parser->buff);

        switch (parser->state){
            case POP3_USER_CMD: {
                parser->state = parse_user_cmd(parser, c);
                break;
            }
            case POP3_USER: {
                parser->state = parse_user(parser, c);
                break;
            }
            case POP3_PASS_CMD: {
                parser->state = parse_pass_cmd(parser, c);
                break;
            }
            case POP3_PASS: {
                parser->state = parse_pass(parser, c);
                break;
            }
            case POP3_ERROR: {
                // TODO: agregar mensaje de error?
                break;
            }
        }
    }
}

void pop3_parser_init(pop3_parser * parser){
    parser = malloc(sizeof(pop3_parser));
    parser->state = POP3_USER_CMD;
    parser->read_ptr = 0;
    parser->write_ptr = 0;
}

pop3_state pop3_parse(pop3_parser * parser, buffer * buff){
    parser->buff.data = buff->data;
    parser->buff.read = buff->read;
    parser->buff.write = buff->write;
    parser->buff.limit = buff->limit;

    pop3_parse_byte(parser);

    pop3_state ret = parser->state;

    if(ret == POP3_DONE)
        pop3_parser_init(parser); //reinicio el parser

    return ret;
}

bool sniffer_is_on(){
    return sniffer_state;
}

void set_sniffer_state(bool newState){
    sniffer_state = newState;
}

