# ftplibpp makefile

SONAME = 2
SOVERSION = $(SONAME).0

TARGETS = libftp++.a libftp++.so
OBJECTS = ftplib.o
SOURCES = ftplib.cpp

CFLAGS = -Wall $(DEBUG) -I. $(INCLUDES) $(DEFINES)
LDFLAGS = -L.
DEPFLAGS =

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
 LIBS = -lssl -lcrypto
endif
ifeq ($(UNAME), Linux)
 LIBS = -lssl
endif

all : $(TARGETS)

clean :
	rm -f $(OBJECTS) core *.bak
	rm -rf unshared
	rm -f $(TARGETS) .depend
	rm -f libftp.so.*

uninstall :
	rm -f /usr/local/lib/libftp.so.*
	rm -f /usr/local/include/libftp.h

install : all
	install -m 644 libftp.so.$(SOVERSION) /usr/local/lib
	install -m 644 ftplib.h /usr/local/include
	(cd /usr/local/lib && \
	 ln -sf libftp.so.$(SOVERSION) libftp.so.$(SONAME) && \
	 ln -sf libftp.so.$(SONAME) libftp.so)

depend :
	$(CC) $(CFLAGS) -M $(SOURCES) > .depend

# build without -fPIC
#unshared/ftplib.o: ftplib.cpp ftplib.h
#	-mkdir unshared
#	$(CC) -c $(CFLAGS) -D_REENTRANT $< -o $@

ftplib.o: ftplib.cpp ftplib.h
	$(CC) -c $(CFLAGS) -fPIC -D_REENTRANT $< -o $@

libftp++.a: ftplib.o
	ar -rcs $@ $<

libftp.so.$(SOVERSION): ftplib.o
	$(CC) -shared -Wl,-soname,libftp.so.$(SONAME) $(LIBS) -lc -o $@ $<

libftp++.so: libftp.so.$(SOVERSION)
	ln -sf $< libftp.so.$(SONAME)
	ln -sf $< $@

ifeq (.depend,$(wildcard .depend))
include .depend
endif
