#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, GetServerHelloFromEthernetFrame ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto& server_hello_packet = packet_data[ 5 ];
    const std::size_t random_pos = 2;
    auto server_hello_result = ntk::get_server_hello_from_ethernet( server_hello_packet );
    ASSERT_TRUE( server_hello_result ) << server_hello_result.error() << std::endl;
    auto& server_hello = server_hello_result.value();
    auto expected_server_version = ntk::tls_version::tls_1_2;
    std::array<uint8_t,32> expected_random;
    std::copy_n( std::begin( test_constants::tls_server_hello ) + random_pos, expected_random.size(), expected_random.begin() );
    ntk::cipher_suite expected_cipher_suite = ntk::cipher_suite::TLS_AES_256_GCM_SHA384;
    auto actual_server_version = server_hello.server_version;
    ntk::cipher_suite actual_cipher_suite = static_cast<ntk::cipher_suite>( server_hello.cipher_suite );
    ASSERT_EQ( actual_server_version, expected_server_version );
    ASSERT_EQ( actual_cipher_suite, expected_cipher_suite );
}

