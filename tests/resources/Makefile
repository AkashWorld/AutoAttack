CFLAGS = -z execstack -fno-stack-protector -no-pie -g -m32 -static

all: simple_buffer.o shellcode

simple_buffer.o: simple_buffer.c
	${CC} ${CFLAGS} $+ -o $@
debug: simple_buffer.c
	${CC} ${CFLAGS} -g $+ -o $@
x86_64_shellcode.o: x86_64_shellcode.asm
	nasm -f elf64 $+
shellcode: x86_64_shellcode.o
	ld -m elf_x86_64 -s -o $@ $+
	chmod +x extraction.sh
	sh extraction.sh > shellcode_encoding
clean:
	rm simple_buffer.o x86_64_shellcode.o shellcode shellcode_encoding
