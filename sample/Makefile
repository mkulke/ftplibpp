.PHONY: all clean test
all: sample

sample.o: sample.cpp ../ftplib.h
	$(COMPILE.cc) -I.. $<

sample: sample.o ../libftp++.a
	$(LINK.cc) -L.. -o $@ $^ ### -lftp++

test: sample
	rm -f sample.bin sample.download
	./sample localhost 2121
	while test ! -f sample.bin; do \
		./sample localhost 2121;   \
	done
	diff sample sample.bin
	./sample 127.0.0.1 2121 --active
	./sample ::ffff:127.0.0.1
	./sample ::1 2121 --active
	-./sample

clean:
	rm -f sample sample.o sample.bin sample.download

