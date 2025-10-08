#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( IntegrationTest, DeriveTlsKeyIv ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& client_hello_packet = packet_data[ 3 ];
    auto client_hello = *ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );
    auto secret = ntk::get_traffic_secret( session_keys, client_hello.random, "CLIENT_TRAFFIC_SECRET_0" );    
    std::string expected_key = "04c5bdf5bccbf7740b09250614979949aa7a6d5b57f4dc15aa8f46fee288c9a4";
    std::string expected_iv = "1cd7b5120945932eb3ca91e5";
    auto km = ntk::derive_tls_key_iv( secret, EVP_sha384(), 32, 12 );
    std::ostringstream oss;
    for ( auto b : km.key ) {
        oss << std::hex << std::setw( 2 ) << std::setfill( '0' )  << static_cast<int>( b );
    }
    std::string actual_key = oss.str();
    ASSERT_EQ( actual_key, expected_key );
    oss.str( "" );
    oss.clear();
    for ( auto b : km.iv ) {
        oss << std::hex << std::setw( 2 ) << std::setfill( '0' )  << static_cast<int>( b );
    }
    std::string actual_iv = oss.str();
    ASSERT_EQ( actual_iv, expected_iv );
}