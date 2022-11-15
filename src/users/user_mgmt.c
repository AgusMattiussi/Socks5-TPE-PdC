#include "user_mgmt.h"

#define MAX_USERS 10

//TODO: Array o listas? Para charlar
static struct user_t * users[MAX_USERS];

uint8_t n_users = 0;

bool valid_credentials(char * username, char * password, char * user2, char * pass2){
    return strcmp(username, user2) == 0 && strcmp(password, pass2) == 0;
}

uint8_t process_authentication_request(char * username, char * password){
    //TODO: Discutir si poner en un 3er parametro un User para que devuelva las credenciales,
    //  o también setear como "currentUser"
    for(int i = 0; i < n_users; i++){
        if(valid_credentials(username, password, users[i]->username, users[i]->password)){
            return 0;
        }
    }

    return 0; //TODO: CHANGE!!!!! Provisorio para probar 
    //return -1;
}