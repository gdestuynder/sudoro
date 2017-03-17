CFLAGS	:= -pie -fPIE -D_FORTIFY_SOURCE=2 -fstack-protector -O2
LDFLAGS := -Wl,-z,relro -Wl,-z,now $(shell pkg-config --libs libcap || echo '-lcap') $(shell pkg-config --libs mount) $(shell pkg-config --libs libseccomp)
LIBTOOL	:= libtool
INSTALL	:= install
VERSION	:= 1.4
# Allow writing to a locally-mounted tmp partition, makes programs less annoying to use, though a little less safe
ALLOW_TMP_WRITE := 1

all: bin flags

release: bin
	strip -s sudoro

bin:
	$(LIBTOOL) --mode=link gcc $(CFLAGS) $(LDFLAGS) -DALLOW_TMP_WRITE=$(ALLOW_TMP_WRITE) sudoro.c -o sudoro

build: bin
	$(INSTALL) -d build/usr/bin
	$(INSTALL) sudoro build/usr/bin

deb: build
	fpm -s dir -t deb -v$(VERSION) -n sudoro --after-install post-install.sh -C build

rpm: build
	fpm -s dir -t rpm -v$(VERSION) -n sudoro --after-install post-install.sh -C build

flags:
	sudo chown root:wheel sudoro
	sudo chmod u+s sudoro
	sudo chmod ug+x sudoro

clean:
	-rm sudoro.o
	-rm -r build
	-rm -f sudoro
	-rm *deb

.PHONY: clean build deb flags
