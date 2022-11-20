#include "include/controlProtocol.h"

static void initStm(struct state_machine * stm);
static controlProtStmState helloWrite(struct selector_key * key);
static void onArrival(controlProtStmState state, struct selector_key *key);
static controlProtStmState authRead(struct selector_key * key);
static controlProtStmState authWrite(struct selector_key * key);
static void onDeparture(controlProtStmState state, struct selector_key *key);
static bool validatePassword(cpAuthParser * authParser);
static unsigned cpError(struct selector_key * key);
static controlProtStmState executeRead(struct selector_key * key);
static controlProtStmState executeWrite(struct selector_key * key);

static int validPassword = false;

static const struct state_definition controlProtStateDef[] = {
    {
        .state = CP_HELLO,
        .on_write_ready = helloWrite
    },
    {
        .state = CP_AUTH,
        .on_arrival = onArrival,
        .on_read_ready = authRead,
        .on_write_ready = authWrite,
        .on_departure = onDeparture
    },
    {
        .state = CP_EXECUTE,
        .on_read_ready = executeRead,
        .on_write_ready = executeWrite
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
    printf("[CP_AUTH/onArrival] Llegue a CP_AUTH\n");
}

static void onDeparture(controlProtStmState state, struct selector_key *key){
    printf("[CP_AUTH/onDeparture] Sali de CP_AUTH\n");
    /* controlProtConn * cpc = (controlProtConn *) key->data;
    initCpAuthParser(&cpc->authParser); */
}

static void initStm(struct state_machine * stm){
    stm->initial = CP_HELLO;
    stm->max_state = CP_ERROR;
    stm->states = (const struct state_definition *) &controlProtStateDef;
    
    stm_init(stm);
}

static unsigned cpError(struct selector_key * key){
    printf("\nERROR CP_ERROR. Reiniciando...\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    initCpAuthParser(&cpc->authParser);
    initCpCommandParser(&cpc->commandParser);
    return CP_HELLO;
}


//TODO: static? Args?
controlProtConn * newControlProtConn(int fd){
    controlProtConn * new = calloc(1, sizeof(controlProtConn));
    
    if(new != NULL){
        initStm(&new->connStm);

        new->readBuffer = malloc(sizeof(buffer));
        if(new->readBuffer == NULL)
            return NULL;

        new->writeBuffer = malloc(sizeof(buffer));
        if(new->writeBuffer == NULL)
            return NULL;
        
        initCpAuthParser(&new->authParser);
        initCpCommandParser(&new->commandParser);
        buffer_init(new->readBuffer, BUFFER_SIZE, new->readBufferData);
        buffer_init(new->writeBuffer, BUFFER_SIZE, new->writeBufferData);
        
        new->fd = fd;
        new->interests = OP_WRITE;  // El protocolo comienza escribiendo HELLO
        new->currentState = CP_HELLO;
    }
    return new;
}

void freeControlProtConn(controlProtConn * cpc, fd_selector s){
    if(cpc == NULL)
        return;

    free(cpc->readBuffer);
    free(cpc->writeBuffer);
    selector_unregister_fd(s, cpc->fd, false);
    close(cpc->fd);
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

/* Escribe en el readBuffer lo que me haya enviado el cliente */
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

void cpCloseHandler(struct selector_key * key){
    freeControlProtConn((controlProtConn *) key->data, key->s);
}


/* ================== Handlers para cada estado de la STM ======================== */

//TODO: Deberia usar el buffer?
static controlProtStmState helloWrite(struct selector_key * key){
    printf("[CP_HELLO]\n");
    controlProtConn * cpc = (controlProtConn *) key->data;

    if(!buffer_can_write(cpc->writeBuffer)){
        //TODO: Manejar error
        printf("[CP_HELLO] Error: !buffer_can_write\n");
    }

    int verLen = strlen(CONTROL_PROT_VERSION);
    int totalLen = verLen + 3; // STATUS = 1  | HAS_DATA = 1 | DATA\n
    
    char * helloMsg = calloc(verLen + 3, sizeof(char));
    sprintf(helloMsg, "%c%c%s\n", STATUS_SUCCESS, 1, CONTROL_PROT_VERSION);

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

/* Lee la contrasenia que envio el usuario y la parsea a una estructura*/
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
    for (int i = 0; i < bytesLeft && parserState != CPAP_DONE; i++){
        cpapParseByte(&cpc->authParser, buffer_read(cpc->readBuffer));
        parserState = cpc->authParser.currentState;

        if(/* parserState == CPAP_DONE || */ parserState == CPAP_ERROR){
            //TODO: Manejar error, (DONE antes de tiempo?)
            printf("[AUTH/authRead] Error: CPAP_ERROR (en for)\n");
            return CP_ERROR;
        }
    }

    //TODO: Puede ser innecesario
    if(parserState == CPAP_ERROR){
        //TODO: Manejar error
        printf("[AUTH/authRead] Error: CPAP_ERROR\n");
        return CP_ERROR;
    }

    if(parserState == CPAP_DONE){
        validPassword = validatePassword(&cpc->authParser);
        selector_set_interest_key(key, OP_WRITE);
        initCpAuthParser(&cpc->authParser); // Reinicio el Parser
    }

    return CP_AUTH;
}

/* Le envia al cliente la respuesta a su autenticacion */
static controlProtStmState authWrite(struct selector_key * key){
    printf("[AUTH] authWrite\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    char authResult[10] = {'\0'};
    int arSize = 0;

    if(!buffer_can_write(cpc->writeBuffer)){
        //TODO: Manejar error
        printf("[AUTH/authWrite] Error: !buffer_can_write\n");
    }

    if(validPassword){
        printf("[AUTH/authWrite] Valid Password!\n");
        authResult[arSize++] = (char) STATUS_SUCCESS; // STATUS = 1 
        authResult[arSize++] = '\0';                  // HAS_DATA = 0
    } else {
        printf("[AUTH/authWrite] Invalid Password :(\n");
        authResult[arSize++] = (char) STATUS_ERROR;   // STATUS = 0 
        authResult[arSize++] = '\1';                  // HAS_DATA = 1
        authResult[arSize++] = (char) CPERROR_INVALID_PASSWORD;
        authResult[arSize++] = '\n';
    }

    size_t maxWrite;
    uint8_t * writePtr = buffer_write_ptr(cpc->writeBuffer, &maxWrite);

    if(arSize > maxWrite){
        //TODO: Buffer lleno. Manejar error
        return CP_ERROR;
    }

    memcpy(writePtr, authResult, arSize);
    buffer_write_adv(cpc->writeBuffer, arSize);

    /* Cambiamos el interes a lectura, para pasar a CP_EXECUTE (o si 
        la contrasenia fue incorrecta, volver a CP_AUTH)*/
    cpc->interests = OP_READ;
    selector_set_interest_key(key, cpc->interests);

    if(!validPassword)
        return CP_AUTH; 
    return CP_EXECUTE;
}

/* Leemos el comando enviado por el usuario */
static controlProtStmState executeRead(struct selector_key * key){
    printf("[EXECUTE] executeRead\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    cpCommandParser * parser =  &cpc->commandParser;


    if(!buffer_can_read(cpc->readBuffer)){
        printf("[EXECUTE/executeRead] Buffer Vacio: !buffer_can_read\n");
        //TODO: Manejar error
        return CP_AUTH;
    }

    size_t bytesLeft;
    buffer_read_ptr(cpc->readBuffer, &bytesLeft);

    if(bytesLeft <= 0){
        printf("[EXECUTE/executeRead] Error: bytesLeft <= 0\n");
        //TODO: Manejar
    }
    
    for(int i = 0; i < bytesLeft && parser->currentState != CPCP_DONE; i++){
        parser->currentState = cpcpParseByte(parser, buffer_read(cpc->readBuffer));
        
        if(parser->currentState == CPCP_ERROR){
            printf("[EXECUTE/executeRead] CPCP_ERROR (en for)\n");
            //TODO: Manejar error
            return CP_ERROR;
        }
    }

    //TODO: Puede ser innecesario
    if(parser->currentState == CPCP_ERROR){
        //TODO: Manejar error
        printf("[EXECUTE/executeRead] Error: CPAP_ERROR\n");
        return CP_ERROR;
    }
    
    if(parser->currentState == CPCP_DONE){
        // TODO: Copiar Comando
        parser->data[parser->dataSize] = '\0';
        printf("\n\nCOMANDO: %d - DATA: %s\n\n", parser->code, parser->data);
        selector_set_interest_key(key, OP_WRITE);
        //initCpCommandParser(parser); // Reinicio el Parser
    }

    return CP_EXECUTE;
}

/* Le enviamos al cliente la respuesta a su comando */

static controlProtStmState executeWrite(struct selector_key * key){
    printf("[EXECUTE] executeWrite\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    cpCommandParser * parser =  &cpc->commandParser;
    char * answer = NULL;

    // TODO: Cambiar por array de punteros a funcion?
    switch (parser->code){
        case CP_ADD_USER:
            addProxyUser(parser, answer);
            break;
        case CP_REM_USER:
            removeProxyUser(parser, answer); 
            break;
        case CP_CHANGE_PASS:
            changePassword(parser, answer);
            break;
        case CP_LIST_USERS:
            getSniffedUsersList(parser, answer);
            break;
        case CP_GET_METRICS:
            getMetrics(parser, answer);
            break;
        case CP_DISSECTOR_ON:
            turnOnPassDissectors(parser, answer);
            break;
        case CP_DISSECTOR_OFF:
            turnOffPassDissectors(parser, answer);
            break;
        default:
            break;
    }

    size_t maxWrite;
    uint8_t * writePtr = buffer_write_ptr(cpc->writeBuffer, &maxWrite);

    int ansSize = strlen(answer);
    if(ansSize > maxWrite){
        //TODO: Buffer lleno. Manejar error
        return CP_ERROR;
    }

    memcpy(writePtr, answer, ansSize);
    buffer_write_adv(cpc->writeBuffer, ansSize);

    cpc->interests |= OP_READ;
    selector_set_interest_key(key, cpc->interests);

    free(answer);
    initCpCommandParser(parser);

    return CP_EXECUTE;
}

