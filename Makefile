#! /usr/bin/make -f

escalator: escalator.o

.PHONY: clean

clean:
	rm -f escalator escalator.o
