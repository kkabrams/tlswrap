sslwrap: CFLAGS=-pedantic -Wall
sslwrap: LDLIBS=-lssl -lcrypto
sslwrap: sslwrap.c
