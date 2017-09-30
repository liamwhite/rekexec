.PHONY: all clean

obj-m += ret2bios.o

# https://unix.stackexchange.com/a/176114
all:
	nasm -o /dev/stdout ret2bios_real.S | hexdump -v -e '16/1 "_x%02X" "\n"' | sed 's/_/\\/g; s/\\x  //g; s/.*/    "&"/' > ret2bios.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f ret2bios.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
