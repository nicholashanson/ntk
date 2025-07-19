#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, GetSnis ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_live_stream" ] );
    auto snis = ntk::get_snis( packet_data, "earthcam" );
    ASSERT_TRUE( !snis.empty() );
}