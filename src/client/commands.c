
#include "commands.h"

char parse_users_message(int fd) {

    uint8_t response_buf[MAXLEN];

    //FIXME: Estaba sin inicializar
    size_t byte_n = MAXLEN;
    ssize_t n_received = recv(fd, response_buf, byte_n, 0);

    if((char)response_buf[0] == FAILURE) {
        if((char)response_buf[1] != SUCCESS)
            return '0';
        return (char)response_buf[2];
    }

    int row_count = (int)response_buf[1];

    char * users = strtok(&response_buf[2], "\n");

    for(int i=0; i<row_count; i++) {
        printf("%s\n", users);
        users = strtok(NULL, "\n");
    }
    
    return '1';
}

char parse_metrics_message(int fd) {

    uint8_t response_buf[MAXLEN];

    //FIXME: Estaba sin inicializar
    size_t byte_n = MAXLEN;
    ssize_t n_received = recv(fd, response_buf, byte_n, 0);

    if((char)response_buf[0] == FAILURE) {
        if((char)response_buf[1] != SUCCESS)
            return '0';
        return (char)response_buf[2];
    }

    char * metrics = strtok(&response_buf[2], "\n");
    printf("%s\n", metrics);
    metrics = strtok(NULL, "\n");
    printf("%s\n", metrics);
    
    return '1';
}

char receive_simple_response(int fd) {
    char response_buf[MAXLEN];

    //FIXME: Estaba sin inicializar
    size_t byte_n = MAXLEN;
    ssize_t n_received = recv(fd, response_buf, byte_n, 0);

    printf("buf: %s\n", response_buf);

    if(response_buf[0] == FAILURE) {
        if(response_buf[1] != SUCCESS)
            return '0';
        return response_buf[2];
    }    
    
    return '1';
}

void help() {
    printf("\nGracias por pedir ayuda! Los comandos son los siguientes:\n");
    printf("adduser <usuario> <pass>: añadir usuario al servidor\n");
    printf("deleteuser <usuario>: eliminar usuario del servidor\n");
    printf("editpass <newpass>: editar contraseña\n");
    printf("list: listar usuarios del servidor\n");
    printf("metrics: obtener métricas de uso del servidor\n");
    printf("dis: prender password dissector\n");
    printf("disoff: apagar password dissector\n");
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

    if(ret == '1')
        return 1;
    printf("Contraseña incorrecta. Por favor, intente nuevamente: ");
    return 0;
}

char add_user(char *username, char * pass, int fd) {
    /*user * new_user = malloc(sizeof(struct user));
    new_user->username = username;
    new_user->password = pass;*/
    size_t len = strlen(username) + strlen(pass) + 4;
    char to_send[MAXLEN] = {0};
    to_send[0] = COMMAND_ADD_USER;
    to_send[1] = HAS_DATA;
    strcat(to_send, username);
    strcat(to_send, ":");
    strcat(to_send, pass);
    to_send[len-1] = '\n';
    send(fd, to_send, len, 0);
    return receive_simple_response(fd);
}

char delete_user(char * username, int fd) {
    size_t len = strlen(username) + 3;
    char to_send[MAXLEN] = {0};
    to_send[0] = COMMAND_DELETE_USER;
    to_send[1] = HAS_DATA;
    strcat(to_send, username);
    to_send[len-1] = '\n';
    send(fd, to_send, len, 0);

    return receive_simple_response(fd);
}

char edit_password(char * pass, int fd) {
    size_t len = strlen(pass) + 3;
    char to_send[MAXLEN] = {0};
    to_send[0] = COMMAND_EDIT_PASSWORD;
    to_send[1] = HAS_DATA;
    strcat(to_send, pass);
    to_send[len-1] = '\n';
    send(fd, to_send, len, 0);

    return receive_simple_response(fd);
}

char list_users(int fd) {
    char to_send[MAXLEN] = {0};
    to_send[0] = COMMAND_LIST_USERS;
    to_send[1] = NO_DATA;
    send(fd, to_send, 2, 0);

    return parse_users_message(fd);
}

char obtain_metrics(int fd) {
    char to_send[MAXLEN] = {0};
    to_send[0] = COMMAND_OBTAIN_METRICS;
    to_send[1] = NO_DATA;
    send(fd, to_send, 2, 0);
    return parse_metrics_message(fd);
}

char dissector_on(int fd) {
    char to_send[MAXLEN] = {0};
    to_send[0] = COMMAND_DISSECTOR_ON;
    to_send[1] = NO_DATA;
    send(fd, to_send, 2, 0);

    return receive_simple_response(fd);
}

char dissector_off(int fd) {
    char to_send[MAXLEN] = {0};
    to_send[0] = COMMAND_DISSECTOR_OFF;
    to_send[1] = NO_DATA;
    send(fd, to_send, 2, 0);

    return receive_simple_response(fd);
}