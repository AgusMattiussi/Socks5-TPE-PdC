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
    printf("\nERROR CP_ERROR. Cerrando Conexion\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    freeControlProtConn(cpc, key->s);
    return CP_ERROR;
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
        new->helloWritten = false;
        new->validPassword = false;
        new->authAnsWritten = false;
        new->execAnsWritten = false;
        new->execAnswer = NULL;
    }
    return new;
}

void freeControlProtConn(controlProtConn * cpc, fd_selector s){
    printf("\nLIBERANDO CPC\n");

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
        //freeControlProtConn(cpc, key->s);
        return;
    }
    // TODO: que pasa si entre aca por segunda vez?

    /* Si hay algo para leer, se lo envio al cliente */
    if(buffer_can_read(cpc->writeBuffer)){
        size_t bytesLeft;
        uint8_t * readPtr = buffer_read_ptr(cpc->writeBuffer, &bytesLeft);

        int bytesSent = send(cpc->fd, readPtr, bytesLeft, 0);
        if(bytesSent <= 0){
            printf("[cpWriteHandler] Error/Closed: bytesSent <= 0\n");
            freeControlProtConn(cpc, key->s);
            return;
        }

        buffer_read_adv(cpc->writeBuffer, bytesSent);

        /* Si no tengo nada mas que enviarle al cliente, apago el interes 
            de escritura */
        //TODO: Funcara? Validar que los parsers esten done?
        /* if(bytesSent == bytesLeft){
            cpc->interests &= !OP_WRITE;
            selector_set_interest_key(key, cpc->interests);
        } */
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
            printf("[cpReadHandler] Error/Closed: bytesRecv <= 0\n");
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
    freeControlProtConn((controlProtConn *) key->data, key->s);
}


/* ================== Handlers para cada estado de la STM ======================== */

/* Escribe en el buffer de escritura el mensaje de HELLO del protocolo*/
static controlProtStmState helloWrite(struct selector_key * key){
    printf("[CP_HELLO]\n");
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
            printf("[CP_HELLO] Error: !buffer_can_write\n");
            return CP_ERROR;
        }
        /*
            +--------+----------+-----------+
            | STATUS | HAS_DATA |   DATA    |
            +--------+----------+-----------+
            | '1'    |        1 | <version> |
            +--------+----------+-----------+
        */
        int verLen = strlen(CONTROL_PROT_VERSION);
        int totalLen = verLen + 4; // STATUS = 1  | HAS_DATA = 1 | DATA\n
        
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
    printf("[AUTH] authRead\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    cpAuthParser * parser =  &cpc->authParser;

    if(!buffer_can_read(cpc->readBuffer)){
        printf("[AUTH/authRead] Buffer Vacio: !buffer_can_read\n");
        //TODO: Si se desperto siempre hay algo para leer no?
        return CP_ERROR;
    }

    size_t bytesLeft;
    /* Voy a leer byte a byte, no necesito el puntero */
    buffer_read_ptr(cpc->readBuffer, &bytesLeft);

    for (int i = 0; i < bytesLeft && parser->currentState != CPAP_DONE; i++){
        parser->currentState = cpapParseByte(parser, buffer_read(cpc->readBuffer));

        if(parser->currentState == CPAP_ERROR){
            printf("[AUTH/authRead] Error: CPAP_ERROR parseando entrada\n");
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
    printf("[AUTH] authWrite\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    char authResult[4];
    int arSize = 0;

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
        printf("[AUTH/authWrite] Error: !buffer_can_write\n");
        return CP_AUTH;
    }

    if(cpc->validPassword){
        printf("[AUTH/authWrite] Valid Password!\n");     
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
        printf("[AUTH/authWrite] Invalid Password :(\n");
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
    printf("[EXECUTE] executeRead\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    cpCommandParser * parser =  &cpc->commandParser;

    if(!buffer_can_read(cpc->readBuffer)){
        printf("[EXECUTE/executeRead] Buffer Vacio: !buffer_can_read\n");
        //TODO: Manejar error
        return CP_AUTH;
    }

    size_t bytesLeft;
    /* Voy a leer byte a byte, no necesito el puntero */
    buffer_read_ptr(cpc->readBuffer, &bytesLeft);
    
    for(int i = 0; i < bytesLeft && parser->currentState != CPCP_DONE; i++){
        parser->currentState = cpcpParseByte(parser, buffer_read(cpc->readBuffer));
        
        if(parser->currentState == CPCP_ERROR){
            printf("[EXECUTE/executeRead] CPCP_ERROR parseando entrada\n");
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
    printf("[EXECUTE] executeWrite\n");
    controlProtConn * cpc = (controlProtConn *) key->data;
    cpCommandParser * parser =  &cpc->commandParser;

    /* Si ya escribi la respuesta y se la envie al cliente, puedo 
        pasar a leer el siguiente comando */
    if(cpc->execAnsWritten && !buffer_can_read(cpc->writeBuffer)){
        printf("Termino el comando\n");
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
        // TODO: Cambiar por array de punteros a funcion
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
            case CP_LIST_USERS:
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
            default:
                break;
        }

        /* Error en malloc */
        if(cpc->execAnswer == NULL){
            printf("[EXECUTE/executeWrite] answer == NULL\n");
            return CP_ERROR;
        }
    }

    size_t maxWrite;
    uint8_t * writePtr = buffer_write_ptr(cpc->writeBuffer, &maxWrite);

    /* Espacio insuficiente en el buffer de escritura para la respuesta. 
        Nos mantenemos en este estado mientras se libera espacio */

    
    int ansSize = strlen(cpc->execAnswer);
    if(ansSize > maxWrite){
        return CP_EXECUTE;
    }

    memcpy(writePtr, cpc->execAnswer, ansSize);
    buffer_write_adv(cpc->writeBuffer, ansSize);

    cpc->execAnsWritten = true;
    initCpCommandParser(&cpc->commandParser);
    return CP_EXECUTE;
}

