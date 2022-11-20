#ifndef CONTROL_PROTOCOL_H
#define CONTROL_PROTOCOL_H

#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "../../include/stm.h"
#include "../../include/buffer.h"
#include "../parsers/cpAuthParser.h"
#include "../parsers/cpCommandParser.h"
#include "cpCommands.h"

#define BUFFER_SIZE 1024
#define HELLO_LEN 10

#define CONTROL_PROT_VERSION "0.1"
#define ADMIN_PASSWORD "pass1234"

#define TOKEN_DELIMITER ";"
#define LINE_DELIMITER "\n"

#define ON 1
#define OFF 0

typedef enum controlProtStmState {
    CP_HELLO,
    CP_AUTH,
    CP_EXECUTE,
    CP_OK,
    CP_ERROR
} controlProtStmState;

typedef enum controlProtStatus{
    STATUS_ERROR = '0',
    STATUS_SUCCESS
} controlProtStatus;

typedef enum controlProtErrorCode{
    CPERROR_INVALID_PASSWORD = '0',
    CPERROR_COMMAND_NEEDS_DATA,
    CPERROR_NO_DATA_COMMAND,
    CPERROR_INVALID_FORMAT,
    CPERROR_INEXISTING_USER,
    CPERROR_ALREADY_EXISTS,
    CPERROR_USER_LIMIT,
    CPERROR_GENERAL_ERROR     /* Encapsulamiento de los errores de memoria */
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