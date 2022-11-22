#include "user_mgmt.h"
#include "../include/args.h"
#include <stdio.h>
#include "../logger/logger.h"

#define MAX_USERS 10

static user_t * users[MAX_USERS];

uint8_t total_users = 0;
bool require_auth;
char * curr_user;

void
init_auth_mgmt(){ require_auth = false; total_users = 0; }

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
    if(curr_user!=NULL) free(curr_user);
}

uint8_t
get_total_curr_users(){
    return total_users;
}

int 
process_authentication_request(char * username, char * password){
    if(!require_auth) return 0; // Que necesidad de chequear si igual no necesita auth.
    for(int i = 0; i < total_users; i++){
        if(valid_credentials(username, password, users[i]->name, users[i]->pass)){
            return 0;
        }
    }
    return -1;
}

int
user_exists(char * username, char * password){
    if(username == NULL || password == NULL){
        LogError("Username or password are invalid.");
        goto finally;
    }
    for(int i = 0; i < total_users; i++){
        if(valid_credentials(username, password, users[i]->name, users[i]->pass)){
            return i;
        }
    }
finally:
    return -1;
}

int
user_exists_by_username(char * username){
    if(username == NULL){
        LogError("Username is invalid.");
        return -1;
    }
    for(int i = 0; i < total_users; i++){
        if(strcmp(username, users[i]->name) == 0){
            return i;
        }
    }
    return -1;
}

enum add_user_state 
add_user(user_t * user){
    printf("Estoy entrando a add_user con parametros %s\t%s\n", user->name, user->pass);
    if(total_users == MAX_USERS){
        LogError("Alcanzaste un máximo de usuarios.\n");
        free(user);
        return ADD_MAX_USERS;
    }
    if(user_exists_by_username(user->name) != -1){
        LogError("Usuario ya existe.\n");
        free(user);
        return ADD_USER_EXISTS;
    }
    users[total_users] = malloc(sizeof(user_t));
    if(users[total_users] == NULL){
        LogError("Error with malloc\n");
        free(user);
        return ADD_ERROR;
    }
    users[total_users]->name = malloc(strlen(user->name) + 1);
    users[total_users]->pass = malloc(strlen(user->pass) + 1);

    if(users[total_users]->name == NULL || users[total_users]->pass == NULL){
        LogError("Error with malloc\n");
        return ADD_ERROR;
    }
    strcpy(users[total_users]->name, user->name);
    strcpy(users[total_users]->pass, user->pass);
    //users[total_users]->name[strlen(users[total_users]->name)] = '\0';
    //users[total_users]->pass[strlen(users[total_users]->pass)] = '\0';
    //free(user->name); free(user->pass);

    total_users++;
    require_auth = true;
    printf("Lo agregue\n");
    return ADD_OK;
}

int 
remove_user(char * username){
    printf("Estoy entrando a remove_user con parametro %s\n", username);

    int pos = user_exists_by_username(username);
    if(pos == -1) {
        LogError("User does not exist."); 
        return -1;
    }
    struct user_t * to_delete = users[pos];
    users[pos] = users[total_users-1];
    free(to_delete->name);
    free(to_delete->pass);
    free(to_delete);
    total_users--;
    printf("LO borre\n");
    return 0;
}

int 
change_password(char * username, char * new_password){
    printf("Estoy entrando a change_pass con parametros %s\t%s\n", username, new_password);

    int pos = user_exists_by_username(username);
    if(pos == -1) {
        LogError("User does not exist."); 
        return -1;
    }
    free(users[pos]->pass);
    users[pos]->pass = malloc(strlen(new_password + 1));
    strcpy(users[pos]->pass, new_password);
    printf("Lo cambie\n");
    return 0;
}

user_t **
get_all_users(){
    printf("Entro a get all users");
    return users;
}

uint8_t 
get_total_users(){ return total_users; }