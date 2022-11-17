#ifndef CONTROL_PROTOCOL_H
#define CONTROL_PROTOCOL_H

#include "../../include/stm.h"
#include "../../include/buffer.h"

#define BUFFER_SIZE 1024

typedef enum controlProtState {
    CP_HELLO,
    CP_AUTH,
    CP_EXECUTE,
    CP_OK,
    CP_ERROR
} controlProtState;

typedef struct controlProtConn {
    // TODO: Manejar datos de la conexion

    buffer * readBuffer;
    buffer * writeBuffer;

    uint8_t readBufferData[BUFFER_SIZE];
    uint8_t writeBufferData[BUFFER_SIZE];

    struct state_machine connStm;
    controlProtState currentState;

} controlProtConn;



#endif