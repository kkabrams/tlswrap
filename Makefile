PREFIX:=/usr/local

.PHONY: install all

all: tlswrap

tlswrap: CFLAGS=-pedantic -Wall
tlswrap: LDLIBS=-lssl -lcrypto
tlswrap: tlswrap.c

install:
	install -Dt $(PREFIX)/bin tlswrap
