#ifndef CONTROL_PROTOCOL_H
#define CONTROL_PROTOCOL_H

#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdbool.h>
#include <string.h>

#include "../../include/stm.h"
#include "../../include/buffer.h"
#include "../parsers/cpAuthParser.h"
#include "../parsers/cpCommandParser.h"

#define BUFFER_SIZE 1024
#define CONTROL_PROT_VERSION "0.1"

#define ADMIN_PASSWORD "pass1234"

#define HELLO_LEN 10

typedef enum controlProtStmState {
    CP_HELLO,
    CP_AUTH,
    CP_EXECUTE,
    CP_OK,
    CP_ERROR
} controlProtStmState;

typedef enum controlProtStatus{
    STATUS_ERROR = 0,
    STATUS_SUCCESS
} controlProtStatus;

typedef enum controlProtErrorCode{
    CPERROR_INVALID_PASSWORD
} controlProtErrorCode;


/* Estructura para manejar los datos de una conexion
    del protocolo de control */
typedef struct controlProtConn {
    // TODO: Manejar datos de la conexion
    int fd;
    int interests;

    buffer * readBuffer;
    buffer * writeBuffer;

    uint8_t readBufferData[BUFFER_SIZE];
    uint8_t writeBufferData[BUFFER_SIZE];

    struct state_machine connStm;
    // TODO: Se usa?
    controlProtStmState currentState;

    //TODO: Deberia ser un puntero? (para que se inicialice a demanda)
    cpAuthParser authParser;
    cpCommandParser commandParser;

    //TODO: Deberia ser una lista?
    //struct controlProtConn * nextConn;

} controlProtConn;

controlProtConn * newControlProtConn(int fd);
void cpWriteHandler(struct selector_key * key);
void cpReadHandler(struct selector_key * key);


#endif