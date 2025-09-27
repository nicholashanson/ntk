#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsDataPacket_TlsHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto result = ntk::is_data_packet( packet_data[ 15 ] );
    ASSERT_TRUE( result ) << result.error() << std::endl; 
    ASSERT_TRUE( result.value() );
}

TEST( UnitTest, IsDataPacket_TlsHandshake_CounterCase ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto result = ntk::is_data_packet( packet_data[ 0 ] );
    ASSERT_TRUE( result ) << result.error() << std::endl; 
    ASSERT_FALSE( result.value() );
}

TEST( UnitTest, IsDataPacket_LongStream ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
    auto result = ntk::is_data_packet( packet_data[ 20 ] );
    ASSERT_TRUE( result ) << result.error() << std::endl; 
    ASSERT_TRUE( result.value() );
}