#include <gtest/gtest.h>

#include <vector>

#include <ipv4.hpp>
#include <udp.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseUdpHeader ) {
    auto ipv4_header_len = *ntk::get_ipv4_header_len_from_ethernet( test::ethernet_frame_udp );
    auto udp_header = ntk::extract_udp_header( test::ethernet_frame_udp, ipv4_header_len );
    ntk::udp_header parsed_udp_header = ntk::parse_udp_header( udp_header );
    ASSERT_EQ( parsed_udp_header.source_port, static_cast<uint16_t>( ntk::port_numbers::HTTPS ) );
}