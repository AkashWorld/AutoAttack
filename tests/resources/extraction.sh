#!/usr/sh
for i in $(objdump -d shellcode |grep "^ " |cut -f2); do echo -n '\x'$i; done; echo
