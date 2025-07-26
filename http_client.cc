#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <memory>
#include <vector>
#include <string>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

namespace simple_ssl {

template <class T> struct DeleterOf;
template<> struct DeleterOf<BIO> {
    void operator()(BIO* bio) const {
        BIO_free(bio);
    }
};
template<> struct DeleterOf<BIO_METHOD> {
    void operator()(BIO_METHOD* method) const {
        BIO_meth_free(method);
    }
};
template<> struct DeleterOf<SSL_CTX> {
    void operator()(SSL_CTX* ctx) const {
        SSL_CTX_free(ctx);
    }
};

template<class OpenSSLType>
using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;

simple_ssl::UniquePtr<BIO> operator|(simple_ssl::UniquePtr<BIO> lower, simple_ssl::UniquePtr<BIO> upper)
{
    BIO_push(upper.get(), lower.release());
    return upper;
}

class StringBIO {
 public:
    StringBIO(StringBIO&&) =delete;
    StringBIO& operator=(StringBIO&&) =delete;

    explicit StringBIO() {
        methods_.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "StringBIO"));
        if (methods_ == nullptr) {
            throw std::runtime_error("StringBIO: error in BIO_meth_new");
        }

        BIO_meth_set_write(methods_.get(), [](BIO *bio, const char *data, int len) -> int {
            std::string *str = reinterpret_cast<std::string*>(BIO_get_data(bio));
            str->append(data, len);
            return len;
        });
        
        bio_.reset(BIO_new(methods_.get()));
        if (bio_ == nullptr) {
            throw std::runtime_error("StringBIO: error in BIO_new");
        }

        BIO_set_data(bio_.get(), &str_);
        BIO_set_init(bio_.get(), 1);
    }

    BIO *bio() {
        return bio_.get();
    }

    std::string str() && {
        return std::move(str_);
    }

 private:
    std::string str_;   
    simple_ssl::UniquePtr<BIO_METHOD> methods_;
    UniquePtr<BIO> bio_;

};

[[noreturn]] void print_errors_and_exit(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

[[noreturn]] void print_errors_and_throw(const char *msg) {
    simple_ssl::StringBIO bio;
    ERR_print_errors(bio.bio());
    throw std::runtime_error(std::string(msg) + "\n" + std::move(bio).str());
}

std::vector<std::string> split_headers(const std::string& text) {
    std::vector<std::string> lines;
    const char *start = text.c_str();
    while (const char *end = strstr(start, "\r\n")) {
        lines.push_back(std::string(start, end));
        start = end + 2;
    }
    return lines;
}

std::string receive_some_data(BIO *bio) {
    char buffer[1024];
    int bytes_read = BIO_read(bio, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        simple_ssl::print_errors_and_throw("error in BIO_read");
    } else if (bytes_read > 0) {
        return std::string(buffer, bytes_read);
    } else if (BIO_should_retry(bio)) {
        return receive_some_data(bio);
    } else {
        simple_ssl::print_errors_and_throw("empty BIO_read");
    }

}

std::string receive_http_response(BIO *bio) {
    std::string headers = simple_ssl::receive_some_data(bio);
    char *end_of_headers = strstr(&headers[0], "\r\n\r\n");
    while (end_of_headers == nullptr) {
        headers += simple_ssl::receive_some_data(bio);
        end_of_headers = strstr(&headers[0], "\r\n\r\n");
    }

    std::string body = std::string(end_of_headers + 4, &headers[headers.size()]);
    headers.resize(end_of_headers + 2 - &headers[0]);
    size_t content_length = 0;
    for (const std::string& line: simple_ssl::split_headers(headers)) {
        if (const char *colon = strchr(line.c_str(), ':')) {
            auto header_name = std::string(&line[0], colon);
            if (header_name == "Content-Length") {
                content_length = std::stoul(colon + 1);
            }
        }
    }

    while (body.size() < content_length) {
        body += simple_ssl::receive_some_data(bio);
    }
    return headers + "\r\n" + body;
}

void send_http_request(BIO *bio, const std::string& line, const std::string& host) {
    std::string request = line + "\r\n" + "Host: " + host + "\r\n" + "\r\n";
    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}

SSL* get_ssl(BIO *bio) {
    SSL *ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (ssl == nullptr) {
        simple_ssl::print_errors_and_exit("Error in BIO_get_ssl");
    }
    return ssl;
}

void verify_the_certificate(SSL *ssl, const std::string& expected_hostname) {
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK) {
        const char *msg = X509_verify_cert_error_string(err);
        fprintf(stderr, "Certificate verification error: %s (%d)\n", msg, err);
        exit(EXIT_FAILURE);
    }
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr) {
        simple_ssl::print_errors_and_exit("No certificate presented by the server");
        exit(EXIT_FAILURE);
    }

    
    if (X509_check_host(cert, expected_hostname.data(), expected_hostname.size(), 0, nullptr) != 1) {
        fprintf(stderr, "Certificate verification error: Hostname mismatch for %s\n", expected_hostname.c_str());
        exit(EXIT_FAILURE);
    }
}

} // namespace simple_ssl

int main() {
    auto ctx = simple_ssl::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
    if (SSL_CTX_set_default_verify_paths(ctx.get()) != 1) {
        simple_ssl::print_errors_and_exit("Error loading trust store");
    }

    auto bio = simple_ssl::UniquePtr<BIO>(BIO_new_connect("duckduckgo.com:443"));
    if (bio == nullptr) {
        simple_ssl::print_errors_and_exit("Error in BIO_new_connect");
    }

    if (BIO_do_connect(bio.get()) <= 0) {
        simple_ssl::print_errors_and_exit("Error in BIO_do_connect");
    }

    auto ssl_bio = std::move(bio) | simple_ssl::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1));
    SSL_set_tlsext_host_name(simple_ssl::get_ssl(ssl_bio.get()), "duckduckgo.com");
    if (BIO_do_handshake(ssl_bio.get()) <= 0) {
        simple_ssl::print_errors_and_exit("Error in TLS handshake");
    }
    simple_ssl::verify_the_certificate(simple_ssl::get_ssl(ssl_bio.get()), "duckduckgo.com");
    
    simple_ssl::send_http_request(ssl_bio.get(), "GET / HTTP/1.1", "duckduckgo.com");
    std::string response = simple_ssl::receive_http_response(ssl_bio.get());
    printf("%s", response.c_str());

    return 0;
}