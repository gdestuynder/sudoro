CFLAGS	:= -pie -fPIE -D_FORTIFY_SOURCE=2 -fstack-protector -O2
LDFLAGS := -Wl,-z,relro -Wl,-z,now $(shell pkg-config --libs libcap) $(shell pkg-config --libs mount) $(shell pkg-config --libs libseccomp)

all: bin flags

release: bin
	strip -s sudoro

bin:
	gcc $(CFLAGS) $(LDFLAGS) sudoro.c -o sudoro

flags:
	sudo chown root:root sudoro
	sudo chmod ug+s sudoro
