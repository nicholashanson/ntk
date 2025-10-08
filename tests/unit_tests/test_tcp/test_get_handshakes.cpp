#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetHandshakes_TLSHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    ASSERT_FALSE( four_tuples.empty() );
    auto four_tuple = four_tuples.begin();
    auto tcp_handshakes = ntk::get_handshakes( packet_data );
    ASSERT_EQ( tcp_handshakes.size(), 1 );
}

TEST( UnitTest, GetHandshakes_Checkerboard ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    ASSERT_FALSE( four_tuples.empty() );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshakes = ntk::get_handshakes( packet_data );
    ASSERT_EQ( tcp_handshakes.size(), 1 );
}

TEST( UnitTest, GetHandshakes_EarthCamVideo ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_video" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    ASSERT_FALSE( four_tuples.empty() );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshakes = ntk::get_handshakes( four_tuple, packet_data );
    ASSERT_EQ( tcp_handshakes.size(), 1 );
}