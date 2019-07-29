CC=gcc
CFLAGS=-g
LD=-Wl,-Bstatic -lcrypto  -Wl,-Bdynamic -no-pie
OBJ=log.o netio.o poll.o socks5.o unit.o sc.o

.PHONY: clean

all: client server

server : ${OBJ}
	 ${CC} -c server.c -o server.o ${CFLAGS}
	${CC}  ${OBJ} server.o -o $@ ${LD}


client : ${OBJ}
	 ${CC} -c client.c -o client.o ${CFLAGS}
	${CC}  ${OBJ} client.o -o $@ ${LD}

${OBJ}: %.o: %.c 
	${CC} -c $< -o $@ ${CFLAGS}


clean:
	-rm *~
	-rm *.o

