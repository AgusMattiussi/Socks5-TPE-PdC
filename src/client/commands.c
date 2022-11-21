
#include "commands.h"

int row_count = 0;

char parse_users_message(int fd, char * offset) {

    uint8_t response_buf[MAXLEN] = {0};

    printf("entrando... offset = %s\n", offset);

    //FIXME: Estaba sin inicializar
    size_t byte_n = MAXLEN;
    ssize_t n_received = recv(fd, response_buf, byte_n, 0);

    if(n_received < 0)
        return '0';

    int pos = 0;
    if(offset == NULL) {
        if((char)response_buf[0] == FAILURE) {
            if(response_buf[1] != HAS_DATA)
                return '0';
            return (char)response_buf[2];
        }
        row_count = (int)response_buf[1];
        pos = 2;
    }

    if(offset==NULL)
        offset = "";

    char str[2] = {0};
    str[0] = TOKEN;

    char * current_user = strtok((char *) &response_buf[pos], str);
    if(response_buf[0] == TOKEN) {
        printf("%s\n", offset);
        printf("%s\n", current_user);
        row_count--;
    } else {
        char aux[MAXLEN] = {0};
        strcat(aux, offset);
        strcat(aux, current_user);

        printf("%s\n", aux);
    }
    
    row_count--;

    while(pos<MAXLEN) {
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
    
    return '1';
}

char parse_metrics_message(int fd) {

    uint8_t response_buf[MAXLEN];

    //FIXME: Estaba sin inicializar
    size_t byte_n = MAXLEN;
    ssize_t n_received = recv(fd, response_buf, byte_n, 0);

    if(n_received < 0)
        return '0';

    if((char)response_buf[0] == FAILURE) {
        if(response_buf[1] != HAS_DATA)
            return '0';
        return (char)response_buf[2];
    }

    char * metrics = strtok((char *)&response_buf[2], "\n");
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

    if(n_received < 0)
        return '0';

    //printf("buf: %s\n", response_buf);

    if((char)response_buf[0] == FAILURE) {
        if(response_buf[1] != HAS_DATA)
            return '0';
        return (char)response_buf[2];
    }    
    
    return '1';
}

void help() {
    printf("\n¡Bienvenido a SCALO_NET! Los comandos disponibles son los siguientes:\n\n");
    printf("adduser <usuario> <pass>: añadir usuario al servidor\n\n");
    printf("deleteuser <usuario>: eliminar usuario del servidor\n\n");
    printf("editpass <newpass>: editar contraseña\n\n");
    printf("list: listar usuarios y contraseñas descubiertas\n\n");
    printf("metrics: obtener métricas de uso del servidor\n\n");
    printf("dis: prender password dissector\n\n");
    printf("disoff: apagar password dissector\n\n");
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
    to_send[1] = HAS_NOT_DATA;
    send(fd, to_send, 2, 0);

    return parse_users_message(fd, NULL);
}

char obtain_metrics(int fd) {
    char to_send[MAXLEN] = {0};
    to_send[0] = COMMAND_OBTAIN_METRICS;
    to_send[1] = HAS_NOT_DATA;
    send(fd, to_send, 2, 0);
    return parse_metrics_message(fd);
}

char dissector_on(int fd) {
    char to_send[MAXLEN] = {0};
    to_send[0] = COMMAND_DISSECTOR_ON;
    to_send[1] = HAS_NOT_DATA;
    send(fd, to_send, 2, 0);

    return receive_simple_response(fd);
}

char dissector_off(int fd) {
    char to_send[MAXLEN] = {0};
    to_send[0] = COMMAND_DISSECTOR_OFF;
    to_send[1] = HAS_NOT_DATA;
    send(fd, to_send, 2, 0);

    return receive_simple_response(fd);
}