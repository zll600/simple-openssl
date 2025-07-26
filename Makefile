.PHONY: http_client
http_client:
	clang++ -std=c++14 http_client.cc $(shell pkg-config --cflags --libs openssl) -o http_client

.PHONY: http_server
http_server:
	clang++ -std=c++14 http_server.cc $(shell pkg-config --cflags --libs openssl) -o http_server

.PHONY: clean
clean:
	rm -f http_client http_server
