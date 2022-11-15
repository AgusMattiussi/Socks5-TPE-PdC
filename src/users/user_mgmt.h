#include <stdint.h>

struct user_t{
    char * username;
    char * password;
};

uint8_t process_authentication_request(char * username, char * password);