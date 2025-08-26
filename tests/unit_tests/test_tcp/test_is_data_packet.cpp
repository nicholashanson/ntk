#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsDataPacket_TlsHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 0 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 1 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 2 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 3 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 4 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 5 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 6 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 7 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 8 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 9 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 10 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 11 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 12 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 13 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 14 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 15 ] ) );
}

TEST( UnitTest, IsDataPacket_LongStream ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream"] );
    auto data_packet = packet_data[ 20 ];
    ASSERT_TRUE( ntk::is_data_packet( data_packet ) ); 
}