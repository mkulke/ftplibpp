.PHONY: all clean test
all: sample

sample.o: sample.cpp ../ftplib.h
	$(COMPILE.cc) -I.. $<

sample: sample.o ../libftp++.a
	$(LINK.cc) -L.. -o $@ $^ ### -lftp++

test: sample
	./sample localhost:2121
	while test ! -f sample.bin; do \
		./sample localhost:2121;   \
	done
	diff sample sample.bin
	-./sample localhost
	-./sample

clean:
	rm -f sample sample.o sample.bin sample.download

