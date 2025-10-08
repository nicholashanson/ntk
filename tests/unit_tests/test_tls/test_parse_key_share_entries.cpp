#include <gtest/gtest.h>

#include <io.hpp>
#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseKeyShareEntries ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto& client_hello_packet = packet_data[ 10 ];
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
    ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
    auto& client_hello = client_hello_result.value();
    auto parse_result = ntk::parse_tls_extensions( client_hello.extensions );
    ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
    auto& extensions = parse_result.value();
    auto key_share_result = ntk::parse_key_share_entries( extensions[ 7 ].value );
    ASSERT_TRUE( key_share_result ) << key_share_result.error() << std::endl;
    auto& key_share_entries = key_share_result.value();
    EXPECT_EQ( key_share_entries.size(), 2 );
}
