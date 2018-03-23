all: qemu-kvm

qemu-kvm: main.o
	gcc main.c -o qemu-kvm -lpthread

clean: 
	rm *.o qemu-kvm
