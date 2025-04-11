all: httpd

httpd:
	g++ -o bin/gpu_node src/*.cc src/*.c -lhv_static -lssl -lcrypto -lstdc++ -lpthread -Wl,-rpath,-Bstatic -ldl

.PHONY: clean
clean:
	rm -f bin/*