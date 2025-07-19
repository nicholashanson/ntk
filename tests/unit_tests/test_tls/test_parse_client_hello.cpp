#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tls.hpp>
#include <io.hpp>

#include <test_tls_handshake_packets.hpp>
#include <test_tcp_handshake_packets.hpp>
#include <test_constants.hpp>

TEST( UnitTest, ParseClientHello ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& tls_client_hello = packet_data[ 3 ];
    ASSERT_EQ( sizeof( test_constants::tls_client_hello_packet ), tls_client_hello.size() );

    auto tls_client_hello_bytes = ntk::get_tcp_payload( test_constants::tls_client_hello_packet );
    ASSERT_EQ( tls_client_hello_bytes.size(), 329 );

    auto tls_record_span = std::span<const uint8_t>( tls_client_hello_bytes );
    auto client_hello_span = tls_record_span.subspan( 9 );
    auto client_hello = ntk::parse_client_hello( client_hello_span );

    ntk::tls_version expected_tls_version = ntk::tls_version::TLS_1_2;
    std::size_t expected_session_id_size = 32;
    std::string expected_session_id = "73a6f6977049af5160801e6221d25c8e4a502f7edcddae5712b90cbcde75d09a";
    std::string expected_client_random = "7ba900c7057e9e5d0609c04b66f56e1b3003cd6906dea3cec057f8f733cc7102";
    std::size_t expected_cipher_suites_size = 62;
    std::size_t expected_compression_methods_size = 1;
    std::size_t expected_extensions_size = 185;

    ntk::tls_version actual_tls_version = client_hello.client_version;
    std::size_t actual_session_id_size = client_hello.session_id.size();
    std::string actual_session_id = ntk::session_id_to_hex( client_hello.session_id );
    std::string actual_client_random = ntk::client_random_to_hex( client_hello.random );
    std::size_t actual_cipher_suites_size = client_hello.cipher_suites.size();
    std::size_t actual_compression_methods_size = client_hello.compression_methods.size();
    std::size_t actual_extensions_size = client_hello.extensions.size();

    ASSERT_EQ( actual_tls_version, expected_tls_version );
    ASSERT_EQ( actual_session_id_size, expected_session_id_size );
    ASSERT_EQ( actual_session_id, expected_session_id );
    ASSERT_EQ( actual_client_random, expected_client_random );
    ASSERT_EQ( actual_cipher_suites_size, expected_cipher_suites_size );
    ASSERT_EQ( actual_compression_methods_size, expected_compression_methods_size );
    ASSERT_EQ( actual_extensions_size, expected_extensions_size );
}