#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, IsSyn_CheckerBoard ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    auto result = ntk::is_syn( packet_data.front() );
    ASSERT_TRUE( result );
    ASSERT_TRUE( result.value() );
}

TEST( UnitTest, IsSyn_LongStrem ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
    auto parse_result = ntk::get_parsed_tcp_header_from_ethernet( packet_data.front() );
    ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
    ASSERT_TRUE( ntk::is_syn( parse_result.value() ) );
} 

TEST( UnitTest, IsSyn_CounterCase ) {
    ASSERT_FALSE( ntk::is_syn( test_constants::tcp_synack_parsed_tcp_header ) );
}