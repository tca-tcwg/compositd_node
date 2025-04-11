all: httpd

httpd:
	g++ -o bin/snp-gpu-httpd src/*.cpp -std=c++11 -lhv -lssl -lcrypto -lstdc++ -lpthread -Wl,-rpath,-Bstatic -ldl

.PHONY: clean
clean:
	rm -f bin/snp-gpu-httpd