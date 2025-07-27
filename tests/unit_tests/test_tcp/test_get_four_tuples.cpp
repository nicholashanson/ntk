#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, GetFourTuples_TLSHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    ASSERT_EQ( four_tuples.size(), 1 ); 
}

TEST( UnitTest, GetFourTuples_Checkerboard ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    ASSERT_EQ( four_tuples.size(), 1 ); 
}

TEST( UnitTest, GetFourTuples_TinyCross ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    ASSERT_EQ( four_tuples.size(), 1 ); 
}