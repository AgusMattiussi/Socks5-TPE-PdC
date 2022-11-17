#ifndef CONN_PARSER_H
#define CONN_PARSER_H
/*

Functions to parse an incoming connection bytes'.

According to protocol (RFC 1928), the connection works like this:

"The client connects to the server, and sends a version
identifier/method selection message:

        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+

The VER field is set to X'05' for this version of the protocol.  The
NMETHODS field contains the number of method identifier octets that
appear in the METHODS field.

The server selects from one of the methods given in METHODS, and
sends a METHOD selection message:

        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+

If the selected METHOD is X'FF', none of the methods listed by the
client are acceptable, and the client MUST close the connection.

The values currently defined for METHOD are:

        o  X'00' NO AUTHENTICATION REQUIRED
        o  X'01' GSSAPI
        o  X'02' USERNAME/PASSWORD
        o  X'03' to X'7F' IANA ASSIGNED
        o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
        o  X'FF' NO ACCEPTABLE METHODS" (Quoted from RFC)

For the scope of this project, we will be covering authentication methods 0x00, and 0x02.
(No auth and user/pass)
*/

#include <stdint.h>
#include "../include/buffer.h"
#include "../include/selector.h"
#include "../include/conn_handler.h"

const static uint8_t SOCKS_VERSION = 0x05;

enum auth_method{
    NO_AUTH = 0x00,
    GSSAPI = 0x01,
    USER_PASS = 0x02,
    NO_METHODS = 0xFF,
};

// States for connection message parsing

enum conn_state{
    CONN_VERSION, 
    CONN_NMETHODS,
    CONN_METHODS,
    CONN_DONE,
    CONN_ERROR,
};

struct conn_parser {
    uint8_t auth;
    enum conn_state state;
    int to_parse;
    char * buff;
};

void start_connection_parser(struct conn_parser * parser);
void conn_parse_byte(struct conn_parser * parser, uint8_t to_parse);
enum conn_state conn_parse_full(struct conn_parser * parser, buffer * buff);
enum conn_state mng_conn_parse_full(struct conn_parser * parser, buffer * buff);

#endif