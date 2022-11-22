
#include "commands.h"

int row_count = 0;

char parse_users_message(int fd, char * offset) {

    uint8_t response_buf[MAXLEN] = {0};
    //FIXME: Estaba sin inicializar
    size_t byte_n = MAXLEN;
    ssize_t n_received = recv(fd, response_buf, byte_n, 0);
    //printf("recibí %s\n", response_buf);
        
    int pos = 0;
    if(offset == NULL) {
        if((char)response_buf[0] == FAILURE) {
            if(response_buf[1] != HAS_DATA)
                return 'x';
            return (char)response_buf[2];
        }
        //row_count = 1;
        row_count = (int)response_buf[1];
        pos = 2;
    }

    if(offset==NULL)
        offset = "";


    char str[2] = {0};
    str[0] = TOKEN;

    char * current_user = strtok((char*)&response_buf[pos], str);
    if(response_buf[0] == TOKEN) {
        printf("%s\n", offset);
        printf("%s\n", current_user);
        row_count--;
    } else {
        //printf("entro 1\n");
        char aux[MAXLEN] = {0};
        strcat(aux, offset);
        strcat(aux, current_user);

        printf("%s\n", aux);
    }
    
    pos += strlen(current_user);
    row_count--;

    //printf("por entrar al while\n");
    while(pos<MAXLEN && row_count > 0) {
        //printf("%c ", response_buf[pos]);
        if(response_buf[pos++] == TOKEN) {
            current_user = strtok(NULL, str);
            row_count--;
            printf("%s\n", current_user);        
        } 
    }

    char str2[2] = {0};
    str2[0] = '\0';

    if(row_count < 0)
        return '0';

    if(row_count > 0) {
        current_user = strtok(NULL, str2);
        if(current_user == NULL)
            current_user = "";
        return parse_users_message(fd, current_user);
    }
    
    return 'i';
}

char parse_metrics_message(int fd) {

    uint8_t response_buf[MAXLEN];

    //FIXME: Estaba sin inicializar
    size_t byte_n = MAXLEN;
    ssize_t n_received = recv(fd, response_buf, byte_n, 0);

    if(n_received < 0)
        return 'x';

    if((char)response_buf[0] == FAILURE) {
        if(response_buf[1] != HAS_DATA)
            return 'x';
        return (char)response_buf[2];
    }

    char str[2] = {0};
    str[0] = TOKEN;

    char * metrics = strtok((char*)&response_buf[2], str);
    printf("%s\n", metrics);
    metrics = strtok(NULL, str);
    printf("%s\n", metrics);
    
    return 'i';
}

char receive_simple_response(int fd) {


    char response_buf[MAXLEN];

    //FIXME: Estaba sin inicializar
    size_t byte_n = MAXLEN;
    ssize_t n_received = recv(fd, response_buf, byte_n, 0);

    if(n_received < 0)
        return 'x';
    

    if((char)response_buf[0] == FAILURE) {
        if(response_buf[1] != HAS_DATA)
            return 'x';
        return (char)response_buf[2];
    }    
    
    return 'i';
}

void help() {
    printf("Welcome to SCALO_NET! The available commands are the following:\n\n");
    printf(" - adduser <user> <pass>: adds a new user to socks5 server\n\n");
    printf(" - deleteuser <user>: delete an existing user from socks5 server\n\n");
    printf(" - editpass <user> <newpass>: edits add existing user password's\n\n");
    printf(" - list: list all users of socks5 server\n\n");
    printf(" - listdiss: lists sniffed pop3 users and passwords\n\n");
    printf(" - metrics: displays server usage metrics\n\n");
    printf(" - dis: turns on the pop3 password dissector\n\n");
    printf(" - disoff: turns off the pop3 password dissector\n\n");
}

void send_simple(int fd, int command) {
    char to_send[MAXLEN] = {0};
    to_send[0] = command;
    to_send[1] = HAS_NOT_DATA;
    send(fd, to_send, 2, 0);
}

int admin_auth(int fd, char * buf) {

    fgets(buf, MAXLEN, stdin);

    buf[strlen(buf)-1] = '\0';

    size_t len = strlen(buf) + 3;
    char to_send[MAXLEN] = {0};
    to_send[0] = COMMAND_AUTH;
    to_send[1] = HAS_DATA;
    strcat(to_send, buf);
    to_send[len-1] = '\n';
    send(fd, to_send, len, 0);

    char ret = receive_simple_response(fd);

    if(ret == 'i')
        return 1;
    printf("Wrong password. Please, try again: ");
    return 0;
}

char single_arg_command(int command, char * username, int fd) {
    size_t len = strlen(username) + 3;
    char to_send[MAXLEN] = {0};
    to_send[0] = command;
    to_send[1] = HAS_DATA;
    strcat(to_send, username);
    to_send[len-1] = '\n';
    send(fd, to_send, len, 0);

    return receive_simple_response(fd);
}

char double_arg_command(int command, char *username, char * pass, int fd) {
    size_t len = strlen(username) + strlen(pass) + 4;
    char to_send[MAXLEN] = {0};
    to_send[0] = command;
    to_send[1] = HAS_DATA;
    strcat(to_send, username);
    strcat(to_send, ":");
    strcat(to_send, pass);
    to_send[len-1] = '\n';
    send(fd, to_send, len, 0);
    return receive_simple_response(fd);
}

char list_users(int command,int fd) {

    send_simple(fd, command);

    return parse_users_message(fd, NULL);
}

char obtain_metrics(int fd) {
    
    send_simple(fd, COMMAND_OBTAIN_METRICS);

    return parse_metrics_message(fd);
}

char dissector(int on, int fd) {
    
    send_simple(fd, on?COMMAND_DISSECTOR_ON:COMMAND_DISSECTOR_OFF);

    return receive_simple_response(fd);
}
