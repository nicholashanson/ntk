#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <requests.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsValidHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ]);
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshake = ntk::get_handshake( four_tuple, packet_data );

    auto syn_header = ntk::get_tcp_header( tcp_handshake.syn.data() );
    auto syn_ack_header = ntk::get_tcp_header( tcp_handshake.syn_ack.data() );
    auto ack_header = ntk::get_tcp_header( tcp_handshake.ack.data() );

    ASSERT_TRUE( ntk::is_valid_handshake( syn_header, syn_ack_header, ack_header ) );
}
