#ifndef AUTH_PARSER_H
#define AUTH_PARSER_H

#include "../include/buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*
Following the connection request and reply, we may now move on to directly using the
server (if no auth was set) or we can enter an user/pass negotiation. For this, the RFC found
at (https://www.rfc-editor.org/rfc/rfc1929) reads the following:

"Once the SOCKS V5 server has started, and the client has selected the
   Username/Password Authentication protocol, the Username/Password
   subnegotiation begins.  This begins with the client producing a
   Username/Password request:

           +----+------+----------+------+----------+
           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
           +----+------+----------+------+----------+
           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
           +----+------+----------+------+----------+
           
           
The VER field contains the current version of the subnegotiation,
   which is X'01'. The ULEN field contains the length of the UNAME field
   that follows. The UNAME field contains the username as known to the
   source operating system. The PLEN field contains the length of the
   PASSWD field that follows. The PASSWD field contains the password
   association with the given UNAME.

   The server verifies the supplied UNAME and PASSWD, and sends the
   following response:

                        +----+--------+
                        |VER | STATUS |
                        +----+--------+
                        | 1  |   1    |
                        +----+--------+

   A STATUS field of X'00' indicates success. If the server returns a
   `failure' (STATUS value other than X'00') status, it MUST close the
   connection.
"

We have 5 parts for the incoming auth request, which will give us 5 + finished/error states
We need to check after parsing the incoming request whether the user exists, and if the credentials
are valid
*/

#define AUTH_VERSION 0x01
#define MAX_LEN 255

enum auth_state{
    AUTH_VER,
    AUTH_ULEN,
    AUTH_UNAME,
    AUTH_PLEN,
    AUTH_PASSWD,
    AUTH_DONE,
    AUTH_ERROR,
};

struct auth_parser{
    enum auth_state state;
    uint8_t to_parse;
    uint8_t * where_to;
    uint8_t username[MAX_LEN];
    uint8_t password[MAX_LEN];
};

void auth_parser_init(struct auth_parser * parser);
enum auth_state auth_parse_full(struct auth_parser * parser, buffer * buff);
enum auth_state mng_auth_parse_full(struct auth_parser * parser, buffer * buff);

#endif