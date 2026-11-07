all:
	clang -g -O2 -target bpf -c exec_kern.c -o exec_kern.o
	bpftool gen skeleton exec_kern.o > exec_kern.skel.h
	gcc -g -O2 -Wall exec_loader.c -o kernel_guard -lbpf -lelf

clean:
	rm -f kernel_guard exec_kern.o *.log
