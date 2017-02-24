CFLAGS	:= -pie -fPIE -D_FORTIFY_SOURCE=2 -fstack-protector -O2
LDFLAGS := -Wl,-z,relro -Wl,-z,now $(shell pkg-config --libs libcap || echo '-lcap') $(shell pkg-config --libs mount) $(shell pkg-config --libs libseccomp)
LIBTOOL	:= libtool

all: bin flags

release: bin
	strip -s sudoro

bin:
	$(LIBTOOL) --mode=link gcc $(CFLAGS) $(LDFLAGS) sudoro.c -o sudoro

build:
	mkdir -p build/usr/bin
	cp sudoro build/usr/bin

deb: build
	fpm -s dir -t deb -v1.0 -n sudoro --after-install post-install.sh -C build

flags:
	sudo chown root:root sudoro
	sudo chmod ug+s sudoro

clean:
	-rm sudoro.o
	-rm -r build
	-rm sudoro
	-rm *deb
