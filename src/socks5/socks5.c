#include "socks5.h"
#include "../stm/stm.h"

//TODO: IMPORTANT! Define functions (where needed) for arrival, read, and write in states.
static const struct state_definition states[] = {
    {
        .state = CONN_READ,
    },
    {
        .state = CONN_WRITE,
    },
    {
        .state = AUTH_READ,
    },
    {
        .state = AUTH_WRITE,
    },
    {
        .state = REQ_READ,
    },
    {
        .state = REQ_RESOLVE,
    },
    {
        .state = REQ_CONNECT,
    },
    {
        .state = REQ_WRITE,
    },
    {
        .state = COPY,
    },
    {
        .state = ERROR,
    },
    {
        .state = DONE,
    }
};

struct state_definition * socks5_all_states(){
    return states;
}
