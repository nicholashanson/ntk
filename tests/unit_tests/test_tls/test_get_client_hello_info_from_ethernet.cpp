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
