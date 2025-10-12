#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <expected>
#include <iostream>
#include <string>
#include <vector>

#include <io.hpp>
#include <tls.hpp>

namespace ntk {

    struct tls_server_config {
        std::vector<cipher_suite> cipher_suites;
        bool respect_client_cipher_suite_preference;
        bool respect_client_key_share_preference;
        std::vector<tls_version> supported_versions;
        std::vector<named_group> key_shares;
    };

    struct server_hello_context {
        cipher_suite c_suite;
        tls_version version;
        std::optional<named_group> key_share;
        std::optional<std::vector<uint8_t>> peer_public_key;
        std::optional<std::vector<uint8_t>> private_key;
        std::optional<std::vector<uint8_t>> public_key;
    };

    std::expected<int,std::string> create_server_socket();

    std::expected<void,std::string> bind_socket( int sock_fd, uint16_t port );

    void handle_client( int client_fd ); 

    std::expected<void,std::string> run_server();

    std::expected<server_hello_context,std::string> get_server_hello_context( const client_hello_info&, const tls_server_config& server_config );

    std::expected<tls_server_config,std::string> get_server_config();

    std::expected<std::vector<uint8_t>,std::string> generate_server_hello( const server_hello_context& context );

} // namespace ntk