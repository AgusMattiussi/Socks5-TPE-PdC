#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include "proto.h"
#include "commands.h"
#include <string.h>
#include "../logger/logger.h"

static char * version;
char * commandStr[] = {
        "help",
        "adduser",
        "deleteuser",
        "editpass",
        "list",
        "metrics",
        "dis",
        "disoff"
};

int mng_connect(char * addr, char * port);
void client_parse_args(int argc, char ** argv, struct proto * args);


int main(int argc, char ** argv) {

    struct proto args;

    char * addr = D_ADDR;
    char * port = D_PORT;

    client_parse_args(argc, argv, &args);

    if(args.addr != NULL) 
        addr = args.addr;

    if(args.port != NULL) 
        port = args.port;   

    int c = mng_connect(addr, port);

    if(c < 0)
        return -1;

    return 0;
	
    
}

void client_parse_args(int argc, char ** argv, struct proto * args) {

    memset(args, 0, sizeof(*args));

    int c;
    while ((c = getopt(argc, argv, "h::p:l")) != -1) {
        switch (c) {
            case 'p':
                args->port = optarg;
                break;
            case 'l':
                args->addr = optarg;
                break;

        }
    }

}

int new_command(int fd, char * buf) {
    fgets(buf, MAXLEN, stdin);

    buf[strlen(buf)-1] = '\0';
 
    char * new_command = strtok(buf, " ");

    char arg[MAXLEN] = {0};
    char arg2[MAXLEN] = {0};
    char * aux;

    int command;
    for(int i=0; i<COMMAND_CANT; i++) {
        if(strcmp(commandStr[i], new_command)==0) {
            command=i+1;
            break;
        }
    }

    char ret;

    switch (command)
        {
        case 1:
            help();
            break;
        case 2: 
            aux = strtok(NULL, " ");
            if(aux == NULL)
                goto error;
            strcpy(arg, aux);
            aux = strtok(NULL, " ");
            if(aux == NULL)
                goto error;
            strcpy(arg2, aux);
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            ret = add_user_mgmt(arg, arg2, fd);
            break;
        case 3:
            aux = strtok(NULL, " ");
            if(aux == NULL)
                goto error;
            strcpy(arg, aux);
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            ret = delete_user(arg, fd);
            break;
        case 4:
            aux = strtok(NULL, " ");
            if(aux == NULL)
                goto error;
            strcpy(arg, aux);
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            ret = edit_password(arg, fd);
            break;
        case 5:
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            list_users(fd);
            break;
        case 6:
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            obtain_metrics(fd);
            break;
        case 7:
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            ret = dissector_on(fd);
            break;
        case 8:
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            ret = dissector_off(fd);
            break;
        default:
            goto error;
        }

    switch (ret)
    {
    case '0':
        printf("Error inesperado del servidor. Cerrando...\n");
        return 1;
        break;
    case '1':
        printf("Success!\n");
        break;
    default:
        break;
    }
    return 0;

    error:
        printf("por favor, ingrese un comando válido\n");
            return 0;
}



int mng_connect(char * addr, char * port) {

    struct addrinfo addrCriteria;                  
	memset(&addrCriteria, 0, sizeof(addrCriteria)); 
	addrCriteria.ai_family = AF_UNSPEC;            
	addrCriteria.ai_socktype = SOCK_STREAM;        
	struct addrinfo *servAddr; 


    int status;
    if ((status = getaddrinfo(addr, port, &addrCriteria, &servAddr)) != 0) {
        return -1;
    }

    int proxy_socket = -1;

    for (struct addrinfo * dir = servAddr; dir != NULL; dir = dir->ai_next) {
        
        proxy_socket = socket(dir->ai_family, dir->ai_socktype, dir->ai_protocol);
        
        if (proxy_socket == -1)
            continue;

        if (connect(proxy_socket, dir->ai_addr, dir->ai_addrlen) != 0)
            continue;


        break;
    }

    int done = 0;
    char buf[MAXLEN];

    size_t byte_n = MAXLEN;
    ssize_t n_received = recv(proxy_socket, buf, byte_n, 0);

    if(buf[0] != SUCCESS || n_received < 0)
        return -1;

    version = &buf[2];

    printf("\nversion: %s\n", version);

    int auth = 0;

    printf("Ingrese su contraseña: ");

    for(int i=0; i<3 && !auth; i++) {
        auth = admin_auth(proxy_socket, buf);
    }

    if(!auth) {
        printf("\nCantidad de intentos excedida. Cerrando conexión...\n");
        return -1;
    }

    
    printf("\n¡Bienvenido a SCALO_NET! Ingrese help para más opciones\n");
    

    while(!done) {
        done = new_command(proxy_socket, buf);
        }
    
    return 0;
}