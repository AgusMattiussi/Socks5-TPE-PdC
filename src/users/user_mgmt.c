#include "user_mgmt.h"
#include "../include/args.h"
#include <stdio.h>

#define MAX_USERS 10

//TODO: Array o listas? Para charlar
static user_t * users[MAX_USERS];

uint8_t n_users = 0;

bool valid_credentials(char * username, char * password, char * user2, char * pass2){
    return strcmp(username, user2) == 0 && strcmp(password, pass2) == 0;
}

uint8_t process_authentication_request(char * username, char * password){
    //TODO: Discutir si poner en un 3er parametro un User para que devuelva las credenciales,
    //  o también setear como "currentUser"
    for(int i = 0; i < n_users; i++){
        if(valid_credentials(username, password, users[i]->name, users[i]->pass)){
            return 0;
        }
    }
    return -1;
}



enum add_user_state add_user(user_t * user){
    if(n_users == MAX_USERS){
        fprintf(stdout, "Alcanzaste un máximo de usuarios.\n");
        free(user);
        return ADD_MAX_USERS;
    }
    if(process_authentication_request(user->name, user->pass) == 0){
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
    return ADD_OK;
}