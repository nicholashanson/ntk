#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, ParseClientHello ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& client_hello_packet = packet_data[ 3 ];
    ASSERT_EQ( sizeof( test_constants::tls_client_hello_packet ), client_hello_packet.size() );
    auto payload_result = ntk::get_tcp_payload( test_constants::tls_client_hello_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    auto& payload = *payload_result.value();
    ASSERT_EQ( payload.size(), 329 );
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
    ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
    auto& client_hello = client_hello_result.value();

    ntk::tls_version expected_tls_version = ntk::tls_version::tls_1_2;
    std::size_t expected_session_id_size = 32;
    std::string expected_session_id = "363c4edf91f14d388547a75f371187ec468d84de548eecfa5dbb4a97390da0a4";
    std::string expected_client_random = "e7bb2bb068dcd517e4f4ba1475e9d936dded3c24627c1b80861f2ca24a645a37";
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

TEST( UnitTest, ParseClientHello_GenerateClientHello ) {
    ntk::generate_default_client_config();
    auto config = ntk::load_client_config();
    auto generate_result = ntk::generate_client_hello( config );
    ASSERT_TRUE( generate_result ) << generate_result.error() << std::endl;
    auto parse_result = ntk::parse_client_hello( generate_result.value().client_hello );
    ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
}