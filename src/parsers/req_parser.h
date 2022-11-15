#ifndef REQ_PARSER_H
#define REQ_PARSER_H

#include "../include/buffer.h"
#include <netinet/in.h>
#include <stdint.h>
#include "conn_parser.h"
#include <stdio.h>
#include <string.h>


/*
4.  Requests

   Once the method-dependent subnegotiation has completed, the client
   sends the request details.  If the negotiated method includes
   encapsulation for purposes of integrity checking and/or
   confidentiality, these requests MUST be encapsulated in the method-
   dependent encapsulation.

   The SOCKS request is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT desired destination port in network octet
             order

   The SOCKS server will typically evaluate the request based on source
   and destination addresses, and return one or more reply messages, as
   appropriate for the request type.


    5.  Addressing

   In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
   the type of address contained within the field:

          o  X'01'

   the address is a version-4 IP address, with a length of 4 octets

          o  X'03'

   the address field contains a fully-qualified domain name.  The first
   octet of the address field contains the number of octets of name that
   follow, there is no terminating NUL octet.

          o  X'04'

   the address is a version-6 IP address, with a length of 16 octets.
*/

#define MAX_FQDN_SIZE 255

#define IPv4_BYTES 4
#define IPv6_BYTES 16


enum req_state{
    REQ_VER,
    REQ_CMD,
    REQ_RSV,
    REQ_ATYP,
    REQ_DST_ADDR,
    REQ_DST_PORT,
    REQ_ERROR,
    REQ_DONE
};

enum res_state{
   RES_SUCCESS = 0x00,
   RES_SOCKS_FAIL = 0x01,
   RES_CONN_FORBIDDEN = 0x02,
   RES_NET_UNREACHABLE = 0x03,
   RES_HOST_UNREACHABLE = 0x04,
   RES_CONN_REFUSED = 0x05,
   RES_TTL_EXPIRED = 0x06,
   RES_CMD_UNSUPPORTED = 0x07,
   RES_ADDR_TYPE_UNSUPPORTED = 0x08,
};

enum req_cmd{
   REQ_CMD_NONE = 0x00, //To initialize
   REQ_CMD_CONNECT = 0x01,
   REQ_CMD_BIND = 0x02,
   REQ_CMD_UDP = 0x03,
};

enum req_atyp{
   ADDR_TYPE_NONE = 0x00, //To initialize
   IPv4 = 0x01,
   FQDN = 0x03,
   IPv6 = 0x04,
};

struct req_dst_addr{
   //TODO: An union might work here aswell
   struct sockaddr_in ipv4;
   struct sockaddr_in6 ipv6;
   uint8_t fqdn[MAX_FQDN_SIZE];
};

struct res_parser{
   enum res_state state;
   enum req_atyp type;
   struct req_dst_addr addr;
   uint16_t port;
};

struct req_parser{
   enum req_state state;
   int to_parse;
   uint8_t * where_to;

   enum req_cmd cmd;
   enum req_atyp type;
   struct req_dst_addr addr;
   uint16_t port;

   struct res_parser res_parser;
};



void req_parser_init(struct req_parser * parser);
#endif