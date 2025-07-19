#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetHandshake_TLSHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshake = *ntk::get_handshake( packet_data );
    ASSERT_EQ( tcp_handshake.syn, packet_data[ to_index( test::tls_handshake::SYN ) ] );
    ASSERT_EQ( tcp_handshake.syn_ack, packet_data[ to_index( test::tls_handshake::SYNACK ) ] );
    ASSERT_EQ( tcp_handshake.ack, packet_data[ to_index( test::tls_handshake::ACK ) ] );
}