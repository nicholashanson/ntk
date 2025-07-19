#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsTcpV_TLShandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto tcp_packets_filter = std::views::all( packet_data ) | std::views::filter( ntk::is_tcp_v );
    auto tcp_packets = std::vector<std::vector<uint8_t>>( tcp_packets_filter.begin(), tcp_packets_filter.end() );
    ASSERT_EQ( tcp_packets.size(), 19 );
}