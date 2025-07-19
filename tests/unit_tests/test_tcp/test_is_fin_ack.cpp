#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsFinAck_EarthCamVideo ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_video" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto num_fin_acks = std::count_if( packet_data.begin(), packet_data.end(), ntk::is_fin_ack );
    ASSERT_EQ( num_fin_acks, 2 );
}

TEST( UnitTest, IsFinAck_TinyCross ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto num_fin_acks = std::count_if( packet_data.begin(), packet_data.end(), ntk::is_fin_ack );
    ASSERT_EQ( num_fin_acks, 2 );
}
