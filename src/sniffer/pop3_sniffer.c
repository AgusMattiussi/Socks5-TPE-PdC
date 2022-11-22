#include "pop3_sniffer.h"

static bool sniffer_state = true;
static const char * pop3_user_cmd = "USER ";
static const char * pop3_pass_cmd = "PASS ";
static users_list * sniffed_users;

users_list * init_users_list() {
    return calloc(1, sizeof(users_list));
}

static void free_node(node * first_node){
    if (first_node == NULL)
           return;
    free_node(first_node->next);
    free(first_node->username);
    free(first_node->password);
    free(first_node);
}

void free_list(users_list * list) {
    if(list != NULL) {
        free_node(list->first);
        free(list);
    }
}

static node * add_rec(node * first, uint8_t * username, uint8_t * password, int * flag) {
    if (first == NULL) {
        node * aux = malloc(sizeof(node));
        aux->username = malloc(sizeof(strlen((char *) username)+1));
        strcpy((char *) aux->username, (char *) username);
        aux->password = malloc(sizeof(strlen((char *)password)+1));
        strcpy((char *) aux->password, (char *) password);
        aux->next = first;
        *flag = 1;
        return aux;
    } else {
        first->next = add_rec(first->next, username, password, flag);
    }
    return first;
}


int add_node(users_list * list, uint8_t * username, uint8_t * password) {
    int added = 0;
    list->first = add_rec(list->first, username, password, &added);
    list->size += added;
    return added;
}

users_list * get_sniffed_users(){
    return sniffed_users;
}


static pop3_state handle_error(pop3_parser * parser, uint8_t c) {
    return parser->user_done? POP3_PASS_CMD : POP3_USER_CMD;
}

static pop3_state parse_user_cmd(pop3_parser * parser, uint8_t c){
    if(toupper(c) == pop3_user_cmd[parser->read_ptr]){
        parser->read_ptr++;
        if(pop3_user_cmd[parser->read_ptr] == '\0') { 
            parser->read_ptr = 0; 
            return POP3_USER;
        }
        return POP3_USER_CMD;
    }
    return handle_error(parser, c);
}

static pop3_state parse_user(pop3_parser * parser, uint8_t c){
    if(parser->write_ptr + 1 == ARGUMENT_LENGTH)
        return POP3_ERROR;

    if(c == '\n'){
        parser->user[parser->write_ptr++] = '\0';
        parser->write_ptr = 0;
        parser->user_done = true;
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
    return handle_error(parser, c);
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

static void pop3_parse_char(pop3_parser * parser){
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
                parser->state = handle_error(parser, c);
                break;
            }
            default:
                break;
        }
    }
}

void pop3_parser_init(pop3_parser * parser){
    parser->state = POP3_USER_CMD;
    parser->read_ptr = 0;
    parser->write_ptr = 0;
    parser->user_done = false;

    if(sniffed_users == NULL) 
        sniffed_users = init_users_list();
}

pop3_state pop3_parse(pop3_parser * parser, buffer * buff){
    parser->buff.data = buff->data;
    parser->buff.read = buff->read;
    parser->buff.write = buff->write;
    parser->buff.limit = buff->limit;

    pop3_parse_char(parser);

    pop3_state ret = parser->state;

    
    if(ret == POP3_DONE) {
        add_node(sniffed_users, parser->user, parser->pass);
        pop3_parser_init(parser); //reinicio el parser
    }

    return ret;
}

bool sniffer_is_on(){
    return sniffer_state;
}

void set_sniffer_state(bool newState){
    sniffer_state = newState;
}
