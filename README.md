## ITBA - "72.07 - Protocolos de Comunicación"
# Trabajo Práctico Especial - 2022/2C - 'Diseño e implementación de un servidor proxy para el protocolo SOCKSv5 [RFC 1928]'

## Introducción
Este trabajo práctico consistió en la implementación de un *proxy SOCKSv5*, siguiendo los lineamientos indicados por el RFC 1928, con la diferencia que este proxy no cuenta con la opción de realizar autenticación mediante *GSSAPI* ni tampoco permite el uso de los comandos *UDP* y *BIND*, propios de *SOCKSv5*.

A su vez, se implementó un protocolo de monitoreo que permite realizar operaciones sobre los usuarios del proxy, consultar diferentes métricas, activar el *dissector* de contraseñas, entre algunas posibilidades.
## Instalación y uso
Para instalar el proxy, es necesario contar con dos dependencias únicamente (normalmente vienen incluidas en cualquier distribución LINUX):
- Make
- GCC

Teniendo estas dos dependencias, realizamos lo siguiente:
1. Nos situamos dentro de la raíz del proyecto (`./TPE-Socks5/`)
2. Allí, corremos el comando `make all`. Esto generará dos ejecutables, que se encontrarán en la carpeta `./bin`:
    - `client`
    - `socks5d`
3. Sin movernos de la raíz del servidor, corremos `./bin/socks5d`, y el servidor comenzará a correr.

## Guía de uso

Las funcionaliades disponibles para ambos ejecutables son:

- Servidor
    - `-h`: Imprime ayuda y termina
    - `-l <addr>`: Dirección donde servirá el proxy SOCKS
    - `-L <addr>`: Dirección donde servirá el servicio de management.
    - `-p <port>`: Puerto entrante conexiones SOCKS.
    - `-P <port>`: Puerto entrante conexiones configuracion
    - `-u <user>:<pass>`: Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.
    - `-N`: Deshabilita los password dissectors
    - `-v`: Imprime información sobre versión y termina
    - `-m`: Activa la opción de logger
    - `-n`: Desactiva la opción de debugger (desactivada por defecto)

- Cliente
    - `help`: Despliega el menú de ayuda
    - `adduser <user> <pass>`: Añade un usuario al servidor
    - `deleteuser <user>`: Elimina un usuario del servidor
    - `editpass <user> <newpass>`: Setea la contraseña *newpass* al usuario *user*
    - `list`: Lista los usuarios actuales del servidor
    - `metrics`: Lista métricas históricas del servidor (conexiones totales y actuales, bytes enviados, etc.)
    - `dis`: Activa el password dissector (Si ya se encontraba activado no tiene efecto)
    - `disoff`: Desactiva el password dissector (Si ya se encontraba desactivado no tiene efecto)

**Aclaración**: Las opciones para el cliente son para ser utilizadas dentro de la negociación, y no mediante línea de comandos.

## Particularidades

El servidor notifica mediante salida estándar cuando detecta una conexión entrante. Esta conexión se describe por una serie de valores que son: 
- Fecha y hora a la cuál se realizó la conexión
- Usuario que la realizó (si no esta autenticado, se reporta como anónimo)
- Dirección de la cual se conecto
- Puerto del cual se conecto
- Dirección a la que se quiere conectar
- Puerto al que se quiere conectar
- Estado de conexión (descripto por el *status code* de *SOCKSv5*)

## Integrantes:
Nombre | Legajo
-------|--------
[De Simone, Franco](https://github.com/desimonef) | 61100
[Dizenhaus, Manuel](https://github.com/ManuelDizen) | 61101
[Mattiussi, Agustín Hernán](https://github.com/AgusMattiussi) | 61361
[Sasso, Julián Martín](https://github.com/JulianSasso) | 61535
