# ftplibpp makefile

SONAME := 2
SOVERSION := $(SONAME).1

TARGETS := libftp++.a ###XXX libftp++.so
OBJECTS := ftplib.o
SOURCES := ftplib.cpp
DEFINES += ###TBD -DNOSSL
DEBUG := -g
CXXWARNFLAGS := -Wold-style-cast -Wsign-conversion -Wconversion -Wsign-compare -Wpointer-arith

CXXFLAGS := -std=c++98 -Wall -Wextra $(CXXWARNFLAGS) $(DEBUG) -I. $(INCLUDES) $(DEFINES)
LDFLAGS := -L.

ifdef TCOV
CXXFLAGS+= --coverage
endif

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
 LIBS = -lssl -lcrypto
endif
ifeq ($(UNAME), Linux)
 LIBS = -lssl
endif

.PHONY: all clean distclean depend install uninstall astyle doc tcov
all : $(TARGETS) doc
	$(MAKE) -C sample test 'CXXFLAGS=$(CXXFLAGS)'

tcov: TCOV=1
tcov: CXXFLAGS+= --coverage
tcov: all
	gcov ftplib

astyle :
	-astyle --style=ansi -t4 *.cpp *.h sample/sample.cpp

doc : README.html
README.html: README.md
	-multimarkdown -o $@ $<
	-tidy -qm -asxml $@

clean :
	rm -f $(OBJECTS)
	rm -f $(TARGETS)
	$(MAKE) -C sample clean

distclean : clean
	rm -f tags core README.html
	rm -f .depend
	rm -f libftp.so.*
	-find . \( -name '*.gcno' -o -name '*.gcda' -o -name '*.gcov' -o -name '*.orig' -o -name '*~' \) -delete
#	rm -rf unshared

uninstall :
	rm -f /usr/local/lib/libftp.so.*
	rm -f /usr/local/include/libftp.h

install : all libftp++.so
	install -m 644 libftp.so.$(SOVERSION) /usr/local/lib
	install -m 644 ftplib.h /usr/local/include
	(cd /usr/local/lib && \
	 ln -sf libftp.so.$(SOVERSION) libftp.so.$(SONAME) && \
	 ln -sf libftp.so.$(SONAME) libftp.so)

depend : .depend
.depend : ftplib.cpp ftplib.h
	$(CXX) $(CXXFLAGS) -M $(SOURCES) > .depend

# build without -fPIC
#unshared/ftplib.o: ftplib.cpp ftplib.h
#	-mkdir unshared
#	$(CXX) -c $(CXXFLAGS) -D_REENTRANT $< -o $@

ftplib.o: ftplib.cpp ftplib.h
	$(CXX) -c $(CXXFLAGS) -fPIC -D_REENTRANT $< -o $@

libftp++.a: $(OBJECTS)
	$(AR) -rcs $@ $<

libftp.so.$(SOVERSION): $(OBJECTS)
	$(CXX) -shared -Wl,-install_name,libftp.so.$(SONAME) $(LIBS) -lc -o $@ $<

libftp++.so: libftp.so.$(SOVERSION)
	ln -sf $< libftp.so.$(SONAME)
	ln -sf $< $@

# include dependency files for any other rule:
ifneq ($(filter-out clean distclean,$(MAKECMDGOALS)),)
-include .depend
endif

