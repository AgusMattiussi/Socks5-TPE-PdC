#include "include/controlProtocol.h"



static const struct state_definition controlProtStateDef = {
    {
        .state = CP_HELLO,
    },
    {
        .state = CP_AUTH,
    },
    {
        .state = CP_EXECUTE,
    },
    {
        .state = CP_OK,
    },
    {
        .state = CP_ERROR,
    },
}


// struct state_definition {
//     /**
//      * identificador del estado: típicamente viene de un enum que arranca
//      * desde 0 y no es esparso.
//      */
//     unsigned state;

//     /** ejecutado al arribar al estado */
//     void     (*on_arrival)    (const unsigned state, struct selector_key *key);
//     /** ejecutado al salir del estado */
//     void     (*on_departure)  (const unsigned state, struct selector_key *key);
//     /** ejecutado cuando hay datos disponibles para ser leidos */
//     unsigned (*on_read_ready) (struct selector_key *key);
//     /** ejecutado cuando hay datos disponibles para ser escritos */
//     unsigned (*on_write_ready)(struct selector_key *key);
//     /** ejecutado cuando hay una resolución de nombres lista */
//     unsigned (*on_block_ready)(struct selector_key *key);
// };
