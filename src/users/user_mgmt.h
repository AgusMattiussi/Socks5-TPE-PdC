#ifndef USER_MGMT_H
#define USER_MGMT_H

#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

struct user_t{
    char * username;
    char * password;
};

uint8_t process_authentication_request(char * username, char * password);

#endif
