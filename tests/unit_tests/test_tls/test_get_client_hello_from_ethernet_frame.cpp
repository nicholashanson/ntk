#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, GetClientHelloFromEthernetFrame_TlsClientHelloPacket ) {
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( test_constants::tls_client_hello_packet );
    ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
    auto& client_hello = client_hello_result.value(); 

    ntk::tls_version expected_tls_version = ntk::tls_version::tls_1_2;
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

TEST( UnitTest, TLSClientHelloFromEthernetFrame_TlsHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto& tls_client_hello = packet_data[ 3 ];
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( tls_client_hello );
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
