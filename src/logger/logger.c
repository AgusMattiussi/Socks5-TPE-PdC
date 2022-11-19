#include "logger.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

/**
 * Implementación de "logger.h".
 */

static bool log = false;

void setLogOn(){ 
	printf("Setting logger ON...\n");
	log = true; }
void setLogOff(){ 
	printf("Setting logger OFF...\n");
	log = false; 
	}

void Log(FILE * const stream, const char * prefix, const char * const format, const char * suffix, va_list arguments) {
	if(log){
	fprintf(stream, "%s", prefix);
	vfprintf(stream, format, arguments);
	fprintf(stream, "%s", suffix);
	}
}

void LogDebug(const char * const format, ...) {
	if(log){
	va_list arguments;
	va_start(arguments, format);
	Log(stdout, "[DEBUG] ", format, "\n", arguments);
	va_end(arguments);
	}
}

void LogError(const char * const format, ...) {
	if(log){
	va_list arguments;
	va_start(arguments, format);
	Log(stderr, "[ERROR] ", format, "\n", arguments);
	va_end(arguments);
	}
}

void LogErrorRaw(const char * const format, ...) {
	if(log){
	va_list arguments;
	va_start(arguments, format);
	Log(stderr, "", format, "", arguments);
	va_end(arguments);
	}
}

void LogInfo(const char * const format, ...) {
	if(log){
	va_list arguments;
	va_start(arguments, format);
	Log(stdout, "[INFO ] ", format, "\n", arguments);
	va_end(arguments);
	}
}
