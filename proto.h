
typedef struct user {
    char * username;
    char * password;
} user;

typedef struct proto {
    struct user current_user;

    char * addr;
    char * port;

} proto;