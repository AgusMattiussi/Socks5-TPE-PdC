#include "include/controlProtocol.h"



static const struct state_definition controlProtStateDef[] = {
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
};


static void initStm(struct state_machine * stm){
    stm->initial = CP_HELLO;
    stm->max_state = CP_ERROR;
    stm->states = (const struct state_definition *) &controlProtStateDef;
    
    stm_init(stm);
}


//TODO: static? Args?
controlProtConn * newControlProtConn(){
    controlProtConn * new = calloc(1, sizeof(controlProtConn));
    
    if(new != NULL){
        initStm(&new->connStm);
        buffer_init(new->readBuffer, BUFFER_SIZE, new->readBufferData);
        buffer_init(new->writeBuffer, BUFFER_SIZE, new->writeBufferData);
        
        new->currentState = CP_HELLO;
    }
    return new;
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
