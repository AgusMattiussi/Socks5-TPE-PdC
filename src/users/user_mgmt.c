#include "user_mgmt.h"
#include "../include/args.h"
#include <stdio.h>
#include "../logger/logger.h"

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

bool
needs_auth(){ return require_auth; }

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
    if(username == NULL || password == NULL){
        LogError("Username or password are invalid.");
        goto finally;
    }
    for(int i = 0; i < n_users; i++){
        if(valid_credentials(username, password, users[i]->name, users[i]->pass)){
            return i;
        }
    }
finally:
    return -1;
}

uint8_t
user_exists_by_username(char * username){
    if(username == NULL){
        LogError("Username is invalid.");
        goto finally;
    }
    for(int i = 0; i < n_users; i++){
        if(strcmp(username, users[i]->name) == 0){
            return i;
        }
    }
finally:
    return -1;
}

enum add_user_state 
add_user(user_t * user){
    if(n_users == MAX_USERS){
        fprintf(stdout, "Alcanzaste un máximo de usuarios.\n");
        free(user);
        return ADD_MAX_USERS;
    }
    if(user_exists_by_username(user->name) != -1){
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

uint8_t 
remove_user(char * username){
    int pos = user_exists_by_username(username);
    if(pos == -1){LogError("User does not exist."); return -1;}
    struct user_t * to_delete = users[pos];
    users[pos] = users[n_users-1];
    free(to_delete->name);
    free(to_delete->pass);
    free(to_delete);
    n_users--;
    return 0;
}

uint8_t 
change_password(char * username, char * new_password){
    int pos = user_exists_by_username(username);
    if(pos == -1){LogError("User does not exist."); return -1;}
    free(users[pos]->pass);
    users[pos]->pass = malloc(strlen(new_password + 1));
    strcpy(users[pos]->pass, new_password);
    return 0;
}
