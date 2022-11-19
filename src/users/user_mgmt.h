#ifndef USER_MGMT_H
#define USER_MGMT_H

#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "../include/args.h"

enum add_user_state{
    ADD_OK,
    ADD_MAX_USERS,
    ADD_USER_EXISTS,
    ADD_ERROR
};

uint8_t process_authentication_request(char * username, char * password);

enum add_user_state add_user(user_t * user);

#endif
