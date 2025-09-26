#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetSni ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
    auto& packet = packet_data[ 3 ];
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( packet );
    ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
    auto result = ntk::get_sni( client_hello_result.value() );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_EQ( result.value(), "videos-3.earthcam.com" );
}