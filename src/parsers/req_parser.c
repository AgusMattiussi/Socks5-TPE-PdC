#include "req_parser.h"
#include "../logger/logger.h"

#define REQ_DST_PORT_BYTES 2
#define FIRST_FQDN_BYTE_PARSE -2
void 
req_parser_init(struct req_parser * parser){
    parser->state = REQ_VER;
    parser->to_parse = 0;
    parser->where_to = NULL;

    parser->cmd = REQ_CMD_NONE;
    parser->type = ADDR_TYPE_NONE;
    parser->port = 0x00;
}

void
set_dst_port_config(struct req_parser * parser){
    parser->to_parse = REQ_DST_PORT_BYTES;
    parser->state = REQ_DST_PORT;
    parser->where_to = (uint8_t *) &(parser->port);
}

void 
parse_addr_byte(struct req_parser * parser, uint8_t to_parse){
    *(parser->where_to++) = to_parse;
    parser->to_parse--;
    if (parser->to_parse == 0) { set_dst_port_config(parser); }
}

void 
req_parse_byte(struct req_parser * parser, uint8_t to_parse){
    switch(parser->state){
        case REQ_VER:
            LogDebug("[REQ_VER] byte to parse %d\n", to_parse);
            if(to_parse == SOCKS_VERSION) parser->state = REQ_CMD;
            else{
                LogError("Request has unsupported version.");
                parser->state = REQ_ERROR;
            }
            break;
        case REQ_CMD:
            LogDebug("[REQ_CMD] byte to parse %d\n", to_parse);
            if(to_parse == REQ_CMD_CONNECT || to_parse == REQ_CMD_BIND ||
            to_parse == REQ_CMD_UDP){
                parser->cmd = to_parse;
                parser->state = REQ_RSV;
            }
            else{parser->state=REQ_ERROR;}
            break;
        case REQ_RSV:
            LogDebug("[REQ_RSV] byte to parse %d\n", to_parse);
            if(to_parse == 0x00) parser->state = REQ_ATYP;
            else{parser->state = REQ_ERROR;}
            break;
        case REQ_ATYP:
            LogDebug("[REQ_ATYP] byte to parse %d\n", to_parse);
            parser->type = to_parse;
            if(to_parse == IPv4){
                memset(&(parser->addr.ipv4), 0, sizeof(parser->addr.ipv4));
                parser->to_parse = IPv4_BYTES;
                parser->addr.ipv4.sin_family = AF_INET;
                parser->where_to = (uint8_t *)&(parser->addr.ipv4.sin_addr);
                parser->state = REQ_DST_ADDR;
            }
            else if(to_parse == IPv6){
                memset(&(parser->addr.ipv6), 0, sizeof(parser->addr.ipv6));
                parser->to_parse = IPv6_BYTES;
                parser->addr.ipv6.sin6_family = AF_INET6;
                parser->where_to = parser->addr.ipv6.sin6_addr.s6_addr;
                parser->state = REQ_DST_ADDR;
            }
            else if(to_parse == FQDN){
                parser->where_to = parser->addr.fqdn;
                parser->to_parse = FIRST_FQDN_BYTE_PARSE;
                parser->state = REQ_DST_ADDR;
            }
            else{
                LogError("Req: Wrong address type");
                parser->state = REQ_ERROR;
            }
            break;
        case REQ_DST_ADDR:
            LogDebug("[REQ_DST_ADDR] byte to parse %d\n", to_parse);

            if(parser->type == FQDN && parser->to_parse == FIRST_FQDN_BYTE_PARSE){
                /* Quoted from RFC: 
                "The first octet of the address field contains the number of 
                octets of name that follow, there is no terminating NUL octet."
                */
                if(to_parse == 0){
                    set_dst_port_config(parser);
                }
                else{
                    parser->to_parse = to_parse;
                    parser->addr.fqdn[parser->to_parse] = 0;
                    parser->state = REQ_DST_ADDR;
                }
            }
            else{ parse_addr_byte(parser, to_parse); }
            break;
        case REQ_DST_PORT:
            LogDebug("[REQ_DST_PORT] byte to parse %d\n", to_parse);
            *(parser->where_to++) = to_parse;
            parser->to_parse--;
            if (parser->to_parse == 0) {
                parser->state = REQ_DONE;
            }
            break;
        case REQ_DONE: case REQ_ERROR: break;
        default:
            LogError("Unrecognized request parsing state, ending parsing");
            break;
    }
}

enum req_state req_parse_full(struct req_parser * parser, buffer * buff){
    while(buffer_can_read(buff)){
        uint8_t to_parse = buffer_read(buff);
        req_parse_byte(parser, to_parse);
        if(parser->state == REQ_ERROR){
            LogError("Error parsing request, returning.");
            return REQ_ERROR;
        }
        if(parser->state == REQ_DONE){break;}
    }
    return parser->state;
}

enum socks_state errno_to_req_response_state(const int e) {
    switch (e) {
    case 0:
        return RES_SUCCESS;
    case ECONNREFUSED:
        return RES_CONN_REFUSED;
    case EHOSTUNREACH:
        return RES_HOST_UNREACHABLE;
    case ENETUNREACH:
        return RES_NET_UNREACHABLE;
    case ETIMEDOUT:
        return RES_TTL_EXPIRED;
    default:
        return RES_CMD_UNSUPPORTED;
    }
}