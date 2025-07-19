#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetTerminations_TinyCross ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_terminations = ntk::get_terminations( four_tuple, packet_data );
    ASSERT_EQ( tcp_terminations.size(), 1 );
}

TEST( UnitTest, GetTerminations_Checkerboard ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_terminations = ntk::get_terminations( four_tuple, packet_data );
    ASSERT_EQ( tcp_terminations.size(), 1 );
}

TEST( UnitTest, GetTerminations_EarthCamVideo ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_video" ]  );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_terminations = ntk::get_terminations( four_tuple, packet_data );
    auto number_of_resets = std::count_if( packet_data.begin(), packet_data.end(), ntk::is_reset );
    ASSERT_EQ( tcp_terminations.size(), number_of_resets );
}