CC=gcc
CFLAGS=-g -fno-stack-protector
LD=-Wl,-Bstatic -lcrypto  -Wl,-Bdynamic
OBJ=log.o netio.o poll.o sc.o socks5.o unit.o num_calc.o modpow.o
VPATH = rsa/big_num:rsa/Montgomery

.PHONY: clean

all: client

client: CFLAGS += -D IS_CLIENT
client: ${OBJ}
	${CC} -c client.c -o client.o ${CFLAGS}
	${CC}  ${OBJ} client.o -o $@ ${LD}

clean:
	-rm *~
	-rm *.o

