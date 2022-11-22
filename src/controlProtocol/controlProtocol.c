#include "include/controlProtocol.h"
#include "../logger/logger.h"

static void initStm(struct state_machine * stm);
static controlProtStmState helloWrite(struct selector_key * key);
static controlProtStmState authRead(struct selector_key * key);
static controlProtStmState authWrite(struct selector_key * key);
static bool validatePassword(cpAuthParser * authParser);
static unsigned cpError(struct selector_key * key);
static controlProtStmState executeRead(struct selector_key * key);
static controlProtStmState executeWrite(struct selector_key * key);

static const struct state_definition controlProtStateDef[] = {
    {
        .state = CP_HELLO,
        .on_write_ready = helloWrite
    },
    {
        .state = CP_AUTH,
        .on_read_ready = authRead,
        .on_write_ready = authWrite
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

static cpConnList * connList;

static bool validatePassword(cpAuthParser * authParser){
    return strcmp(ADMIN_PASSWORD, authParser->inputPassword) == 0 ? true : false;
}

static void initStm(struct state_machine * stm){
    stm->initial = CP_HELLO;
    stm->max_state = CP_ERROR;
    stm->states = (const struct state_definition *) &controlProtStateDef;
    
    stm_init(stm);
}

static unsigned cpError(struct selector_key * key){
    LogError("\nERROR CP_ERROR. Cerrando Conexion\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    freeControlProtConn(cpc, key->s);
    return CP_ERROR;
}

static void initConnList(){
    connList = malloc(sizeof(cpConnList));
    connList->size = 0;
    connList->first = NULL;
}

static void addToList(controlProtConn * new){
    if(connList->first == NULL){
        connList->first = new;
        return;
    }
    
    controlProtConn * current = connList->first;
    while (current->nextConn != NULL){
        current = current->nextConn;
    }
    current->nextConn = new;
    connList->size++;
}

/* Hay que liberar el nodo despues de desencadenarlo! */
static controlProtConn * removeRec(controlProtConn * current, int fd, int * removed){
    if(current == NULL)  
        return NULL;

    if(current->fd == fd){
        controlProtConn * aux = current->nextConn;
        current->nextConn = NULL;
        *removed = 1;
        return aux;
    }
    current->nextConn = removeRec(current->nextConn, fd, removed);
    return current;
}

/* Hay que liberar el nodo despues de desencadenarlo! */
static void removeFromList(controlProtConn * toRem){
    int removed = 0;
    connList->first = removeRec(connList->first, toRem->fd, &removed);
    connList->size -= removed;
}


static void freeRec(controlProtConn * current){
    if(current == NULL)
        return;
    freeRec(current->nextConn);
    LogInfo("Liberando fd: %d\n", current->fd);
    freeControlProtConn(current, current->s);
}

void freeCpConnList(){
    if(connList == NULL)
        return;
    
    freeRec(connList->first);
    return;
}


controlProtConn * newControlProtConn(int fd, fd_selector s){
    controlProtConn * new = calloc(1, sizeof(controlProtConn));
    if(connList == NULL)
        initConnList();
    
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
        new->s = s;
        new->interests = OP_WRITE;  // El protocolo comienza escribiendo HELLO
        new->currentState = CP_HELLO;
        new->helloWritten = false;
        new->validPassword = false;
        new->authAnsWritten = false;
        new->execAnsWritten = false;
        new->execAnswer = NULL;

        addToList(new);
    }
    return new;
}

void freeControlProtConn(controlProtConn * cpc, fd_selector s){
    LogInfo("\nLIBERANDO CPC\n");

    if(cpc == NULL)
        return;

    free(cpc->readBuffer);
    free(cpc->writeBuffer);
    //free(cpc->execAnswer);
    selector_unregister_fd(s, cpc->fd, false);
    close(cpc->fd);
    free(cpc);
    remove_current_mgmt_connection();
    //TODO: Descontar de las conexiones actuales en metrics
}

/* =========================== Handlers para el fd_handler =============================*/

/* Lee del writeBuffer lo que haya dejado el servidor del protocolo 
    de control y se lo envia al cliente */
void cpWriteHandler(struct selector_key * key){
    controlProtConn * cpc = (controlProtConn *) key->data;

    /* Llamo a la funcion de escritura de este estado. 
        Actualizo el estado actual */
    cpc->currentState = stm_handler_write(&cpc->connStm, key);
    if(cpc->currentState == CP_ERROR){
        return;
    }

    /* Si hay algo para leer, se lo envio al cliente */
    if(buffer_can_read(cpc->writeBuffer)){
        size_t bytesLeft;
        uint8_t * readPtr = buffer_read_ptr(cpc->writeBuffer, &bytesLeft);

        int bytesSent = send(cpc->fd, readPtr, bytesLeft, 0);
        if(bytesSent <= 0){
            LogError("[cpWriteHandler] Error/Closed: bytesSent <= 0\n");
            removeFromList(cpc);
            freeControlProtConn(cpc, key->s);
            return;
        }

        buffer_read_adv(cpc->writeBuffer, bytesSent);
    }

}

/* Escribe en el readBuffer lo que me haya enviado el cliente */
void cpReadHandler(struct selector_key * key){
    controlProtConn * cpc = (controlProtConn *) key->data;

    /* Solo recibo bytes del cliente si aun tengo espacio en el 
       buffer de lectura. Si no, llamo al handler de lectura para 
       que consuma los que pueda */
    if(buffer_can_write(cpc->readBuffer)){
        size_t bytesLeft;
        uint8_t * readPtr = buffer_write_ptr(cpc->readBuffer, &bytesLeft);

        int bytesRecv = recv(cpc->fd, readPtr, bytesLeft, 0);
        if(bytesRecv <= 0){
            LogError("[cpReadHandler] Error/Closed: bytesRecv <= 0\n");
            removeFromList(cpc);
            freeControlProtConn(cpc, key->s);
            return;
        }

        buffer_write_adv(cpc->readBuffer, bytesRecv);
    }

    /* Llamo a la funcion de lectura de este estado. 
        Actualizo el estado actual */
    cpc->currentState = stm_handler_read(&cpc->connStm, key);
    //TODO: Validar CP_ERROR
}

/* Libera los recursos de esta conexion */
void cpCloseHandler(struct selector_key * key){
    controlProtConn * aux = (controlProtConn *) key->data;
    removeFromList(aux);
    freeControlProtConn(aux, key->s);
}


/* ================== Handlers para cada estado de la STM ======================== */

/* Escribe en el buffer de escritura el mensaje de HELLO del protocolo*/
static controlProtStmState helloWrite(struct selector_key * key){
    LogInfo("[CP_HELLO]\n");
    controlProtConn * cpc = (controlProtConn *) key->data;

    /* Si ya envie el HELLO al cliente, paso al estado de CP_AUTH */
    if(cpc->helloWritten && !buffer_can_read(cpc->writeBuffer)){
        cpc->interests = OP_READ;
        selector_set_interest_key(key, cpc->interests);
        return CP_AUTH;
    }

    /* Si no envie el HELLO, lo pongo en el buffer de escritura */
    if(!cpc->helloWritten) {
        /* En el estado HELLO, el buffer de escritura deberia estar vacio */
        if(!buffer_can_write(cpc->writeBuffer)){
            LogError("[CP_HELLO] Error: !buffer_can_write\n");
            return CP_ERROR;
        }
        /*
            +--------+----------+-----------+
            | STATUS | HAS_DATA |   DATA    |
            +--------+----------+-----------+
            | '1'    |        1 | <version> |
            +--------+----------+-----------+
        */
        size_t verLen = strlen(CONTROL_PROT_VERSION);
        size_t totalLen = verLen + 4; // STATUS = 1  | HAS_DATA = 1 | DATA\n
        
        char * helloMsg = calloc(totalLen, sizeof(char));
        sprintf(helloMsg, "%c%c%s\n", STATUS_SUCCESS, 1, CONTROL_PROT_VERSION);

        size_t maxWrite;
        uint8_t * bufPtr = buffer_write_ptr(cpc->writeBuffer, &maxWrite);

        /* En el estado HELLO, el buffer de escritura deberia estar vacio */
        if(totalLen > maxWrite){
            return CP_ERROR;
        }

        memcpy(bufPtr, helloMsg, totalLen);
        buffer_write_adv(cpc->writeBuffer, totalLen);

        free(helloMsg);

        cpc->helloWritten = true;
    }

    /* Sigo en CP_HELLO hasta haber enviado el HELLO */
    return CP_HELLO;
}

/* Lee la contrasenia que envio el usuario y la parsea a una estructura*/
static controlProtStmState authRead(struct selector_key * key){
    LogInfo("[AUTH] authRead\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    cpAuthParser * parser =  &cpc->authParser;

    /* Si el cpReadHandler se desperto, siempre deberia haber algo
        para leer del readBuffer */
    if(!buffer_can_read(cpc->readBuffer)){
        LogInfo("[AUTH/authRead] Buffer Vacio: !buffer_can_read\n");
        return CP_ERROR;
    }

    size_t bytesLeft;
    /* Voy a leer byte a byte, no necesito el puntero */
    buffer_read_ptr(cpc->readBuffer, &bytesLeft);

    for (size_t i = 0; i < bytesLeft && parser->currentState != CPAP_DONE; i++){
        parser->currentState = cpapParseByte(parser, buffer_read(cpc->readBuffer));

        if(parser->currentState == CPAP_ERROR){
            LogError("[AUTH/authRead] Error: CPAP_ERROR parseando entrada\n");
            return CP_ERROR;
        }
    }

    /* Cuando termine de leer satisfactoriamente (al encontrar '\n'), cambio el
        interes a OP_WRITE para responderle al cliente */
    if(parser->currentState == CPAP_DONE){
        cpc->validPassword = validatePassword(&cpc->authParser);
        selector_set_interest_key(key, OP_WRITE);
        initCpAuthParser(&cpc->authParser);         // Reinicio el Parser
    }

    return CP_AUTH;
}

/* Le envia al cliente la respuesta a su autenticacion */
static controlProtStmState authWrite(struct selector_key * key){
    LogError("[AUTH] authWrite\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    char authResult[4];
    size_t arSize = 0;

    /* Si ya escribi la respuesta y se la envie al cliente, puedo 
        pasar al siguiente estado */
    if(cpc->authAnsWritten && !buffer_can_read(cpc->writeBuffer)){
        cpc->interests = OP_READ;
        selector_set_interest_key(key, cpc->interests);
        return CP_EXECUTE;
    }

    /* Si ya escribi la respuesta, no queda nada por hacer 
        hasta que TCP la haya enviado */
    if(cpc->authAnsWritten)
        return CP_AUTH;


    /* Si el buffer de escritura esta lleno, no puedo seguir escribiendo 
        en el hasta no haberle enviado mas bytes al cliente */
    if(!buffer_can_write(cpc->writeBuffer)){
        LogError("[AUTH/authWrite] Error: !buffer_can_write\n");
        return CP_AUTH;
    }

    if(cpc->validPassword){
        LogError("[AUTH/authWrite] Valid Password!\n");     
        /* 
            +--------+----------+------+
            | STATUS | HAS_DATA | DATA |
            +--------+----------+------+
            |      1 |        0 |      |
            +--------+----------+------+
        */
        authResult[arSize++] = (char) STATUS_SUCCESS; // STATUS = 1 
        authResult[arSize++] = '\0';                  // HAS_DATA = 0
    } else {
        /* 
            +--------+----------+--------------+
            | STATUS | HAS_DATA |     DATA     |
            +--------+----------+--------------+
            |      0 |        1 | <error-code> |
            +--------+----------+--------------+ 
        */
        LogError("[AUTH/authWrite] Invalid Password :(\n");
        authResult[arSize++] = (char) STATUS_ERROR;   // STATUS = 0 
        authResult[arSize++] = '\1';                  // HAS_DATA = 1
        authResult[arSize++] = (char) CPERROR_INVALID_PASSWORD;
        authResult[arSize++] = '\n';
    }

    size_t maxWrite;
    uint8_t * writePtr = buffer_write_ptr(cpc->writeBuffer, &maxWrite);

    /* Espacio insuficiente en el buffer de escritura para la respuesta. 
        Nos mantenemos en este estado mientras se libera espacio */
    if(arSize > maxWrite){
        return CP_AUTH;
    }

    memcpy(writePtr, authResult, arSize);
    buffer_write_adv(cpc->writeBuffer, arSize);

    /* Si la contraseña es invalida, volvemos a CP_AUTH para que el cliente 
        intente nuevamente */
    if(!cpc->validPassword){
        cpc->interests = OP_READ;
        selector_set_interest_key(key, cpc->interests);
        return CP_AUTH;
    }

    cpc->authAnsWritten = true;
    return CP_AUTH;
}

/* Leemos el comando enviado por el cliente */
static controlProtStmState executeRead(struct selector_key * key){
    LogError("[EXECUTE] executeRead\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    cpCommandParser * parser =  &cpc->commandParser;

    /* Si ya escribi la respuesta y se la envie al cliente, puedo 
        pasar al siguiente estado */
    if(!buffer_can_read(cpc->readBuffer)){
        LogError("[EXECUTE/executeRead] Buffer Vacio: !buffer_can_read\n");
        return CP_AUTH;
    }

    size_t bytesLeft;
    /* Voy a leer byte a byte, no necesito el puntero */
    buffer_read_ptr(cpc->readBuffer, &bytesLeft);
    
    for(size_t i = 0; i < bytesLeft && parser->currentState != CPCP_DONE; i++){
        parser->currentState = cpcpParseByte(parser, buffer_read(cpc->readBuffer));
        
        if(parser->currentState == CPCP_ERROR){
            LogError("[EXECUTE/executeRead] CPCP_ERROR parseando entrada\n");
            return CP_ERROR;
        }
    }
    
    /* Cuando termine de leer el comando, cambio el interes a escritura para 
        responderle al cliente */
    if(parser->currentState == CPCP_DONE){
        /* Cerramos el string con un '\0' */
        parser->data[parser->dataSize] = '\0';
        cpc->interests = OP_WRITE;
        selector_set_interest_key(key, cpc->interests);
    }

    return CP_EXECUTE;
}

/* Le enviamos al cliente la respuesta a su comando */
static controlProtStmState executeWrite(struct selector_key * key){
    LogError("[EXECUTE] executeWrite\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    cpCommandParser * parser =  &cpc->commandParser;

    /* Si ya escribi la respuesta y se la envie al cliente, puedo 
        pasar a leer el siguiente comando */
    if(cpc->execAnsWritten && !buffer_can_read(cpc->writeBuffer)){
        cpc->execAnsWritten = false;
        cpc->interests = OP_READ;
        selector_set_interest_key(key, cpc->interests);
        free(cpc->execAnswer);
        cpc->execAnswer = NULL;
        return CP_EXECUTE;
    }

    /* Si ya escribi la respuesta, no queda nada por hacer 
        hasta que TCP la haya enviado */
    if(cpc->execAnsWritten){
        return CP_EXECUTE;
    }

    /* Solo generamos la respuesta una vez por cada comando */

    /**     
     * Respuesta Exitosa
     *  +--------+-------------+------------+
     *  | STATUS |  HAS_DATA   |    DATA    |
     *  +--------+-------------+------------+
     *  |      1 | <row-count> | <csv-data> |
     *  +--------+-------------+------------+
     * 
     * Respuesta con Error
     *  +--------+----------+--------------+
     *  | STATUS | HAS_DATA |     DATA     |
     *  +--------+----------+--------------+
     *  |      0 |        1 | <error-code> |
     *  +--------+----------+--------------+
     * 
    **/
    if(cpc->execAnswer == NULL){
        // TODO: Cambiar por array de punteros a funcion (Para la proxima ;) )
        switch (parser->code){
            case CP_ADD_USER:
                cpc->execAnswer = addProxyUser(parser);
                break;
            case CP_REM_USER:
                cpc->execAnswer = removeProxyUser(parser); 
                break;
            case CP_CHANGE_PASS:
                cpc->execAnswer = changePassword(parser);
                break;
            case CP_LIST_USERS_DISSEC:
                cpc->execAnswer = getSniffedUsersList(parser);
                break;
            case CP_GET_METRICS:
                cpc->execAnswer = getMetrics(parser);
                break;
            case CP_DISSECTOR_ON:
                cpc->execAnswer = turnOnPassDissectors(parser);
                break;
            case CP_DISSECTOR_OFF:
                cpc->execAnswer = turnOffPassDissectors(parser);
                break;
            case CP_LIST_USERS:
                cpc->execAnswer = getSocksUsers(parser);
                break;
            default:
                break;
        }

        /* Error en malloc */
        if(cpc->execAnswer == NULL){
            LogError("[EXECUTE/executeWrite] answer == NULL\n");
            return CP_ERROR;
        }
    }

    size_t maxWrite;
    uint8_t * writePtr = buffer_write_ptr(cpc->writeBuffer, &maxWrite);

    /* Espacio insuficiente en el buffer de escritura para la respuesta. 
        Nos mantenemos en este estado mientras se libera espacio */

    
    size_t ansSize = strlen(cpc->execAnswer);
    if(ansSize > maxWrite){
        return CP_EXECUTE;
    }

    memcpy(writePtr, cpc->execAnswer, ansSize);
    buffer_write_adv(cpc->writeBuffer, ansSize);

    cpc->execAnsWritten = true;
    initCpCommandParser(&cpc->commandParser);
    return CP_EXECUTE;
}

