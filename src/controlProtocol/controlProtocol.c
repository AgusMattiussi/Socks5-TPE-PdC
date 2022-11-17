#include "include/controlProtocol.h"

static void initStm(struct state_machine * stm);
static controlProtStmState helloHandler(struct selector_key * key);

static const struct state_definition controlProtStateDef[] = {
    {
        .state = CP_HELLO,
        .on_write_ready = helloHandler
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
controlProtConn * newControlProtConn(int fd){
    controlProtConn * new = calloc(1, sizeof(controlProtConn));
    
    if(new != NULL){
        initStm(&new->connStm);
        buffer_init(new->readBuffer, BUFFER_SIZE, new->readBufferData);
        buffer_init(new->writeBuffer, BUFFER_SIZE, new->writeBufferData);
        
        new->fd = fd;
        new->currentState = CP_HELLO;
    }
    return new;
}

//TODO: Deberia usar el buffer?
static controlProtStmState helloHandler(struct selector_key * key){
    controlProtConn * cpc = (controlProtConn *) key->data;

    int verLen = strlen(CONTROL_PROT_VERSION);

    char helloMsg[HELLO_LEN] = {'\0'};
    helloMsg[0] = STATUS_SUCCESS; // Status: Success
    helloMsg[1] = 1; // HAS_DATA: 1 linea
    memcpy(&helloMsg[2], CONTROL_PROT_VERSION, verLen);
    helloMsg[verLen + 3] = '\n';
    int totalLen = verLen + 4;

    size_t maxWrite;
    uint8_t * bufPtr = buffer_write_ptr(cpc->writeBuffer, &maxWrite);

    if(totalLen > maxWrite){
        //TODO: Manejar error
        //return CP_ERROR;
    }

    memcpy(bufPtr, helloMsg, totalLen);
    buffer_write_adv(cpc->writeBuffer, totalLen);
    return CP_AUTH;
}




