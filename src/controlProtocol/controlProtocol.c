#include "include/controlProtocol.h"

static void initStm(struct state_machine * stm);
static controlProtStmState helloStartWrite(struct selector_key * key);
static controlProtStmState helloWrite(struct selector_key * key);

static const struct state_definition controlProtStateDef[] = {
    {
        .state = CP_HELLO_START,
        .on_write_ready = helloStartWrite
    },
    {
        .state = CP_HELLO_WRITE,
        .on_write_ready = helloWrite
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
    stm->initial = CP_HELLO_START;
    stm->max_state = CP_ERROR;
    stm->states = (const struct state_definition *) &controlProtStateDef;
    
    stm_init(stm);
}


//TODO: static? Args?
controlProtConn * newControlProtConn(int fd){
    controlProtConn * new = calloc(1, sizeof(controlProtConn));
    
    if(new != NULL){
        initStm(&new->connStm);

        new->readBuffer = malloc(sizeof(buffer));
        new->writeBuffer = malloc(sizeof(buffer));
        if(new->readBuffer == NULL || new->writeBuffer == NULL){
            //TODO: Manejar Error
        }

        buffer_init(new->readBuffer, BUFFER_SIZE, new->readBufferData);
        buffer_init(new->writeBuffer, BUFFER_SIZE, new->writeBufferData);
        
        new->fd = fd;
        new->currentState = CP_HELLO_START;
    }
    return new;
}

void freeControlProtConn(controlProtConn * cpc){
    if(cpc == NULL)
        return;

    free(cpc->readBuffer);
    free(cpc->writeBuffer);
    free(cpc);
}

//TODO: Deberia usar el buffer?
static controlProtStmState helloStartWrite(struct selector_key * key){
    controlProtConn * cpc = (controlProtConn *) key->data;

    int verLen = strlen(CONTROL_PROT_VERSION);

    /* Mensaje de HELLO */
    char helloMsg[HELLO_LEN] = {'\0'};
    helloMsg[0] = STATUS_SUCCESS;       // Status: Success
    helloMsg[1] = 1;                    // HAS_DATA: 1 linea
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

    //TODO: Necesario?
    selector_set_interest_key(key, OP_WRITE);
    return CP_HELLO_WRITE;
}


static controlProtStmState helloWrite(struct selector_key * key){
    controlProtConn * cpc = (controlProtConn *) key->data;

    size_t bytesLeft;
    uint8_t * bufPtr = buffer_read_ptr(cpc->writeBuffer, &bytesLeft);

    int bytesSent = send(key->fd, bufPtr, bytesLeft, 0);

    if(bytesSent <= 0){
        //TODO: Manejar error
    }

    buffer_read_adv(cpc->writeBuffer, bytesSent);

    if(bytesSent < bytesLeft) // Todavia queda parte del HELLO por enviar
        return CP_HELLO_WRITE;

    // Termine de enviar el HELLO
    selector_set_interest_key(key, OP_READ);
    return CP_AUTH;
}

static controlProtStmState authRead(struct selector_key * key){
    controlProtConn * cpc = (controlProtConn *) key->data;
}


