#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, GetSniToIp ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_live_stream" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto sni_2_ip = ntk::get_sni_to_ip( packet_data );
    ASSERT_FALSE( sni_2_ip.empty() );
    ASSERT_TRUE( sni_2_ip.contains( "videos-3.earthcam.com" ) );
}
