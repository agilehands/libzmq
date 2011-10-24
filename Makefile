all:
	./autogen.sh
	./configure
	make -f Makefilezmq
	sudo make -f Makefilezmq install