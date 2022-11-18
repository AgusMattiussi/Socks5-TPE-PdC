#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>

#include "include/args.h"

static char * port(char * s) {
    char * end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end ||
        ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 ||
        sl > USHRT_MAX) {
        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
        return NULL;
    }
    return s;
}

static void
user(char *s) {
    user_t * user = malloc(sizeof(user_t));

    char *p = strchr(s, ':');
    if(p == NULL) {
        fprintf(stderr, "password not found\n");
        exit(1);
    } else {
        *p = 0;
        p++;
        user->name = s;
        user->pass = p;
    }
    add_user(user);
}

static void
version(void) {
    fprintf(stderr, "socks5v version 0.0\n"
                    "ITBA Protocolos de Comunicación 2022/2 -- Grupo 3\n"
                    "AQUI VA LA LICENCIA\n");
}

static void
usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTION]...\n"
        "\n"
        "   -h               Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
        "   -L <conf  addr>  Dirección donde servirá el servicio de management.\n"
        "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
        "   -P <conf port>   Puerto entrante conexiones configuracion\n"
        "   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
        "   -v               Imprime información sobre la versión versión y termina.\n"
        "\n"
        "   --doh-ip    <ip>    \n"
        "   --doh-port  <port>  XXX\n"
        "   --doh-host  <host>  XXX\n"
        "   --doh-path  <host>  XXX\n"
        "   --doh-query <host>  XXX\n"

        "\n",
        progname);
    exit(1);
}

void parse_args(int argc, char ** argv, struct socks5args * args) {
    memset(args, 0, sizeof(*args));

    args->socks_addr = NULL;
    args->socks_port = "1080";

    args->mng_addr = NULL;
    args->mng_port = "8080";

    int ret_code = 0;

    int c;
    while (true) {
        c = getopt(argc, argv, "hl:L:Np:P:U:u:v");
        if (c == -1)
            break;
        switch (c) {
            case 'h':
                usage(argv[0]);
                    goto finally;
            case 'l':
                args->socks_addr = optarg;
                break;
            case 'L':
                args->mng_addr = optarg;
                break;
            case 'N':
                //change_dissector_state(false);
                break;
            case 'p':
                args->socks_port = port(optarg);
                if (args->socks_port == NULL) {
                    ret_code = 1;
                    goto finally;
                }
                break;
            case 'P':
                args->mng_port = port(optarg);
                if (args->mng_port == NULL) {
                    ret_code = 1;
                    goto finally;
                }
                break;
            case 'u': 
                user(optarg);
                break;
            case 'v':
                version();
                goto finally;
            default:
                fprintf(stderr, "unknown argument %d.\n", c);
                ret_code = 1;
                goto finally;
            }
    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        ret_code = 1;
        goto finally;
    }

finally:
    if (ret_code) {
        //free_users();
        exit(ret_code);
    }
}
