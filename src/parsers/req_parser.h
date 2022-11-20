#ifndef REQ_PARSER_H
#define REQ_PARSER_H

#include "../include/buffer.h"
#include <netinet/in.h>
#include <stdint.h>
#include "conn_parser.h"
#include <stdio.h>
#include <string.h>

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

enum req_state req_parse_full(struct req_parser * parser, buffer * buff);
enum res_state errno_to_req_response_state(const int e) ;

#endif