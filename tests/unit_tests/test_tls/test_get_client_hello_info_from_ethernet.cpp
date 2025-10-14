#include <gtest/gtest.h>

#include <io.hpp>
#include <tls.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, GetClientHelloInfo ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto& client_hello_packet = packet_data[ 10 ];
    auto parse_result = ntk::get_client_hello_info_from_ethernet( client_hello_packet );
    ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
    auto& info = parse_result.value();
    EXPECT_EQ( info.extensions, test_constants::c_hello_extensions );
}

TEST( UnitTest, GetClientHelloInfo_GenerateClientHello ) {
    ntk::generate_default_client_config();
    auto config_result = ntk::load_client_config();
    ASSERT_TRUE( config_result ) << config_result.error() << std::endl;
    auto client_hello_result = ntk::generate_client_hello( config_result.value() );
    ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
    auto& client_hello = client_hello_result.value().client_hello;
    auto info_result = ntk::get_client_hello_info( client_hello );
    ASSERT_TRUE( info_result ) << info_result.error() << std::endl;
    auto& info = info_result.value();
    ASSERT_TRUE( info.extensions );
    auto& extensions = info.extensions.value();
    ASSERT_TRUE( extensions.supported_groups );
    EXPECT_EQ( extensions.supported_groups.value().size(), 6 );
    EXPECT_EQ( info.cipher_suites.size(), 17 );
    EXPECT_EQ( extensions.key_share_entries->size(), 2 );
    EXPECT_EQ( static_cast<ntk::named_group>( extensions.key_share_entries->front().group ), ntk::named_group::x25519 );
    EXPECT_EQ( extensions.key_share_entries->front().key_data.size(), 32 );
    EXPECT_EQ( static_cast<ntk::named_group>( extensions.key_share_entries->back().group ), ntk::named_group::secp256r1 );
    EXPECT_EQ( extensions.key_share_entries->back().key_data.size(), 65 );
}