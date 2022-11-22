#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include "proto.h"
#include <string.h>

#define D_ADDR "127.0.0.1"
#define D_PORT "8080"
#define FAILURE '0'
#define SUCCESS '1'
#define COMMAND_AUTH '0'
#define COMMAND_ADD_USER '1'
#define COMMAND_DELETE_USER '2'
#define COMMAND_EDIT_PASSWORD '3'
#define COMMAND_LIST_DISSECTOR '4'
#define COMMAND_OBTAIN_METRICS '5'
#define COMMAND_DISSECTOR_ON '6'
#define COMMAND_DISSECTOR_OFF '7'
#define COMMAND_LIST_USERS '8'
#define COMMAND_CANT 10
#define HAS_NOT_DATA 0
#define HAS_DATA 1
#define MAXLEN 1024
#define TOKEN '\n'

void help() ;
int admin_auth(int fd, char * buf);
char single_arg_command(int command, char * username, int fd);
char double_arg_command(int command, char * username, char * pass, int fd);
char list_users(int command, int fd);
char obtain_metrics(int fd);
char dissector(int on, int fd);


#endif

