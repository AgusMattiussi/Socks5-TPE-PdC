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

int proxy_socket = -1;
static int cmd = -1;
static char * version;
char * commandStr[] = {
        "help",
        "adduser",
        "deleteuser",
        "editpass",
        "listdiss",
        "metrics",
        "dis",
        "disoff",
        "list"
};

typedef enum controlProtErrorCode{
    CPERROR_INVALID_PASSWORD = '0',
    CPERROR_COMMAND_NEEDS_DATA,
    CPERROR_NO_DATA_COMMAND,
    CPERROR_INVALID_FORMAT,
    CPERROR_INEXISTING_USER,
    CPERROR_ALREADY_EXISTS,
    CPERROR_USER_LIMIT,
    CPERROR_GENERAL_ERROR     /* Encapsulamiento de los errores de memoria */
} controlProtErrorCode;

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
        printf("Connection failed\n");

    return 0;
	
    
}

void
retain_cmd(int new_cmd){
    cmd = new_cmd;
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

int analyze_return(char ret) {
    switch (ret)
    {
    case 'x':
        printf("Unexpected server error. Closing...\n");
        return 1;
    case 'i':
        if(cmd != 1 && cmd != 6 && cmd != 9) printf("OK!\n");
        break;
    case CPERROR_ALREADY_EXISTS:
        printf("Error: user already exists\n");
        break;
    case CPERROR_COMMAND_NEEDS_DATA:
        printf("Error: command needs data\n");
        break;
    case CPERROR_GENERAL_ERROR:
        printf("Unexpected server error\n");
        return 1;
    case CPERROR_INEXISTING_USER:
        printf("Error: user does not exist\n");
        break;
    case CPERROR_INVALID_FORMAT:
        printf("Error: invalid format\n");
        break;
    case CPERROR_NO_DATA_COMMAND:
        printf("Error: command doesn't allow data\n");
        break;
    case CPERROR_USER_LIMIT:
        printf("Error: user limit reached\n");
        break;
    default:
        break;
    }
    return 0;
}

int new_command() {

    char buf[MAXLEN] = {0};
 
    fgets(buf, MAXLEN, stdin);

    buf[strlen(buf)-1] = '\0';
 
    char * new_command = strtok(buf, " ");

    char arg[MAXLEN] = {0};
    char arg2[MAXLEN] = {0};
    char * aux;

    int command = -1;
    for(int i=0; i<COMMAND_CANT; i++) {
        if(strcmp(commandStr[i], new_command)==0) {
            command=i+1;
            break;
        }
    }
    retain_cmd(command);
    char ret;

    switch (command)
        {
        case 1:
            help();
            break;
        case 2: 
            aux = strtok(NULL, " ");
            if(aux == NULL)
                goto not_enough_args;
            strcpy(arg, aux);
            aux = strtok(NULL, " ");
            if(aux == NULL)
                goto not_enough_args;
            strcpy(arg2, aux);
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto too_many_args;
            ret = double_arg_command(COMMAND_ADD_USER, arg, arg2, proxy_socket);
            break;
        case 3:
            aux = strtok(NULL, " ");
            if(aux == NULL)
                goto not_enough_args;
            strcpy(arg, aux);
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto too_many_args;
            ret = single_arg_command(COMMAND_DELETE_USER, arg, proxy_socket);
            break;
        case 4:
            aux = strtok(NULL, " ");
            if(aux == NULL)
                goto not_enough_args;
            strcpy(arg, aux);
            aux = strtok(NULL, " ");
            if(aux == NULL)
                goto not_enough_args;
            strcpy(arg2, aux);
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            ret = double_arg_command(COMMAND_EDIT_PASSWORD, arg, arg2, proxy_socket);
            break;
        case 5:
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            ret = list_users(COMMAND_LIST_DISSECTOR, proxy_socket);
            break;
        case 6:
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            ret = obtain_metrics(proxy_socket);
            break;
        case 7:
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            ret = dissector(1, proxy_socket);
            break;
        case 8:
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            ret = dissector(0, proxy_socket);
            break;
        case 9:
            aux = strtok(NULL, " ");
            if(aux != NULL)
                goto error;
            ret = list_users(COMMAND_LIST_USERS, proxy_socket);
            break;
        default:
            goto error;
        }


    return analyze_return(ret);

    error:
        printf("Please, enter a valid command\n");
            return 0;
    
    not_enough_args:
        printf("Not enough arguments. Check out \"help\"!\n");
        return 0;
    
    too_many_args:
        printf("Too many arguments. Check out \"help\"!\n");
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

    printf("Password: ");

    for(int i=0; i<3 && !auth; i++) {
        auth = admin_auth(proxy_socket, buf);
    }

    if(!auth) {
        printf("\nToo many failed attempts. Closing...\n");
        return -1;
    }

    
    printf("\nWelcome! Use \"help\" for more options\n");
    

    while(!done) {
        done = new_command();
        }
    
    return 0;
}