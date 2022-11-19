#include "user_mgmt.h"
#include "../include/args.h"
#include <stdio.h>

#define MAX_USERS 10

static user_t * users[MAX_USERS];

uint8_t n_users = 0;
bool require_auth;
char * curr_user;

void
init_auth_mgmt(){ require_auth = false; n_users = 0; }

bool 
valid_credentials(char * username, char * password, char * user2, char * pass2){
    return strcmp(username, user2) == 0 && strcmp(password, pass2) == 0;
}

char *
get_curr_user(){ return curr_user; }

void
set_curr_user(char * username){
    curr_user = malloc(sizeof(strlen(username)));
    memcpy(curr_user, username, strlen(username));
}

void
free_curr_user(){
    if(curr_user!=NULL)free(curr_user);
}

uint8_t
get_total_curr_users(){
    return n_users;
}

uint8_t 
process_authentication_request(char * username, char * password){
    if(!require_auth) return 0; // Que necesidad de chequear si igual no necesita auth.
    for(int i = 0; i < n_users; i++){
        if(valid_credentials(username, password, users[i]->name, users[i]->pass)){
            return 0;
        }
    }
    return -1;
}

uint8_t
user_exists(char * username, char * password){
    for(int i = 0; i < n_users; i++){
        if(valid_credentials(username, password, users[i]->name, users[i]->pass)){
            return 0;
        }
    }
    return -1;
}

enum add_user_state 
add_user(user_t * user){
    if(n_users == MAX_USERS){
        fprintf(stdout, "Alcanzaste un máximo de usuarios.\n");
        free(user);
        return ADD_MAX_USERS;
    }
    if(user_exists(user->name, user->pass) == 0){
        fprintf(stdout, "Usuario ya existe.\n");
        free(user);
        return ADD_USER_EXISTS;
    }
    users[n_users] = malloc(sizeof(user_t));
    if(users[n_users] == NULL){
        fprintf(stdout, "Error with malloc\n");
        free(user);
        return ADD_ERROR;
    }
    users[n_users]->name = malloc(strlen(user->name));
    users[n_users]->pass = malloc(strlen(user->pass));
    if(users[n_users]->name == NULL || users[n_users]->pass == NULL){
        fprintf(stdout, "Error with malloc\n");
        return ADD_ERROR;
    }
    strcpy(users[n_users]->name, user->name);
    strcpy(users[n_users]->pass, user->pass);
    n_users++;
    require_auth = true;
    return ADD_OK;
}