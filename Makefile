.PHONY: http_client
http_client:
	clang++ -std=c++14 http_client.cc $(shell pkg-config --cflags --libs openssl) -o http_client

.PHONY: clean
clean:
	rm -f http_client