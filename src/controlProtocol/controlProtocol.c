#include "include/controlProtocol.h"

static void initStm(struct state_machine * stm);
static controlProtStmState helloWrite(struct selector_key * key);
static void onArrival(controlProtStmState state, struct selector_key *key);
static controlProtStmState authRead(struct selector_key * key);
static void onDeparture(controlProtStmState state, struct selector_key *key);
static bool validatePassword(cpAuthParser * authParser);
static void cpError(struct selector_key * key);

static int validPassword = false;

static const struct state_definition controlProtStateDef[] = {
    {
        .state = CP_HELLO_START,
        .on_write_ready = helloWrite
    },
    /* {
        .state = CP_HELLO_WRITE,
        .on_write_ready = helloWrite
    }, */
    {
        .state = CP_AUTH,
        .on_arrival = onArrival,
        .on_read_ready = authRead,
        .on_departure = onDeparture
    },
    {
        .state = CP_EXECUTE,
    },
    {
        .state = CP_OK,
    },
    {
        .state = CP_ERROR,
        .on_read_ready = cpError,
        .on_write_ready = cpError,
    },
};

static bool validatePassword(cpAuthParser * authParser){
    return strcmp(ADMIN_PASSWORD, authParser->inputPassword) == 0 ? true : false;
}

static void onArrival(controlProtStmState state, struct selector_key *key){
    printf("Llegue a CP_AUTH\n");
}

static void onDeparture(controlProtStmState state, struct selector_key *key){
    printf("Sali de CP_AUTH\n");
}

static void initStm(struct state_machine * stm){
    stm->initial = CP_HELLO_START;
    stm->max_state = CP_ERROR;
    stm->states = (const struct state_definition *) &controlProtStateDef;
    
    stm_init(stm);
}

static void cpError(struct selector_key * key){
    printf("ERROR CP_ERROR");
    abort();
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
        //TODO: Cambiar esto al onArrival?
        initCpAuthParser(&new->authParser);
        buffer_init(new->readBuffer, BUFFER_SIZE, new->readBufferData);
        buffer_init(new->writeBuffer, BUFFER_SIZE, new->writeBufferData);
        
        new->fd = fd;
        new->interests = OP_WRITE;  // El protocolo comienza escribiendo HELLO
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

/* =========================== Handlers para el fd_handler =============================*/

/* Lee del writeBuffer lo que haya dejado el servidor del protocolo 
    de control y se lo envia al cliente */
void cpWriteHandler(struct selector_key * key){
    controlProtConn * cpc = (controlProtConn *) key->data;

    /* Llamo a la funcion de escritura de este estado. 
        Actualizo el estado actual */
    cpc->currentState = stm_handler_write(&cpc->connStm, key);

    if(!buffer_can_read(cpc->writeBuffer)){
        // TODO: No hay bytes para leer. Manejar error
        printf("[cpWriteHandler] Error: buffer_can_read fallo\n");
        return;
    }

    size_t bytesLeft;
    uint8_t * readPtr = buffer_read_ptr(cpc->writeBuffer, &bytesLeft);

    int bytesSent = send(cpc->fd, readPtr, bytesLeft, 0);
    if(bytesSent <= 0){
        //TODO: Error o conexion cerrada. Manejar
        printf("[cpWriteHandler] Error: bytesSent <= 0\n");
        return;
    }

    buffer_read_adv(cpc->writeBuffer, bytesSent);
}


void cpReadHandler(struct selector_key * key){
    controlProtConn * cpc = (controlProtConn *) key->data;

    if(!buffer_can_write(cpc->readBuffer)){
        // TODO: Buffer lleno. Manejar error
        printf("[cpReadHandler] Error: buffer_can_write fallo\n");
        return;
    }

    size_t bytesLeft;
    uint8_t * readPtr = buffer_write_ptr(cpc->readBuffer, &bytesLeft);

    int bytesRecv = recv(cpc->fd, readPtr, bytesLeft, MSG_DONTWAIT);
    if(bytesRecv <= 0){
        //TODO: Error o conexion cerrada. Manejar
        printf("[cpReadHandler] Error: bytesRecv <= 0\n");
        return;
    }

    buffer_write_adv(cpc->readBuffer, bytesRecv);

    /* Llamo a la funcion de lectura de este estado. 
        Actualizo el estado actual */
    cpc->currentState = stm_handler_read(&cpc->connStm, key);
}

/* ================== Handlers para cada estado de la STM ======================== */

//TODO: Deberia usar el buffer?
static controlProtStmState helloWrite(struct selector_key * key){
    printf("[CP_HELLO_START]");
    controlProtConn * cpc = (controlProtConn *) key->data;

    int verLen = strlen(CONTROL_PROT_VERSION);
    int totalLen = verLen + 3; // STATUS | HAS_DATA | DATA\n
    
    char * helloMsg = calloc(verLen + 3, sizeof(char));
    sprintf(helloMsg, "%hhx%hhx%s\n", 1, 1, CONTROL_PROT_VERSION);

    size_t maxWrite;
    uint8_t * bufPtr = buffer_write_ptr(cpc->writeBuffer, &maxWrite);

    if(totalLen > maxWrite){
        //TODO: Manejar error
        //return CP_ERROR;
    }

    memcpy(bufPtr, helloMsg, totalLen);
    buffer_write_adv(cpc->writeBuffer, totalLen);

    free(helloMsg);

    //TODO: Necesario?
    cpc->interests = OP_READ;
    selector_set_interest_key(key, cpc->interests);
    return CP_AUTH;
}


static controlProtStmState authRead(struct selector_key * key){
    printf("[AUTH] authRead\n");
    controlProtConn * cpc = (controlProtConn *) key->data;

    if(!buffer_can_read(cpc->readBuffer)){
        printf("[AUTH/authRead] Buffer Vacio: !buffer_can_read\n");
        //TODO: Manejar error
        return CP_AUTH;
    }

    size_t bytesLeft;
    buffer_read_ptr(cpc->readBuffer, &bytesLeft);

    if(bytesLeft <= 0){
        printf("[AUTH/authRead] Error: bytesLeft <= 0\n");
        //TODO: Manejar
    }

    cpAuthParserState parserState;
    for (int i = 0; i < bytesLeft; i++){
        cpapParseByte(&cpc->authParser, buffer_read(cpc->readBuffer));
        parserState = cpc->authParser.currentState;

        if(/* parserState == CPAP_DONE || */ parserState == CPAP_ERROR){
            //TODO: Manejar error, (DONE antes de tiempo?)
            printf("[AUTH/authRead] Error: CPAP_ERROR (en for)\n");
            return CP_ERROR;
        }
    }

    if(parserState == CPAP_ERROR){
        //TODO: Manejar error
        printf("[AUTH/authRead] Error: CPAP_ERROR\n");
        return CP_ERROR;
    }

    if(parserState == CPAP_DONE){
        validPassword = validatePassword(&cpc->authParser);
        selector_set_interest_key(key, OP_WRITE);
        printf("%s\n", validPassword ? "CONTRASENIA CORRECTA":"CONTRASENIA INCORRECTA");
    }

    return CP_AUTH;
}


