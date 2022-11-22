#ifndef PROTO_H
#define PROTO_H

typedef struct proto {
    struct user current_user;

    char * addr;
    char * port;

} proto;

#endif