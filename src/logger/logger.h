/*
*                                   LOGGER.h 
*
*       A simple logger to use for debugging purposes
*       This logger has been designed and used as part of a base project
*       for the subject "Automata and theory of languages".
*       
*       Author: Agustín Golmar
*       Original project with the logger can be found at:
*       https://github.com/agustin-golmar/Flex-Bison-Compiler
*
*/

#ifndef LOGGER_HEADER
#define LOGGER_HEADER

#include <stdio.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

#include "../socks5/socks5.h"
#include "../users/user_mgmt.h"
#include "../sniffer/pop3_sniffer.h"
#include "../include/netutils.h"

void setLogOn();
void setLogOff();

void Log(FILE * const stream, const char * prefix, const char * const format, const char * suffix, va_list arguments);

void LogDebug(const char * const format, ...);

void LogError(const char * const format, ...);

void LogErrorRaw(const char * const format, ...);

void LogInfo(const char * const format, ...);

#endif
