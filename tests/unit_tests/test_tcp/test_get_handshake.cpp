#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetHandshake_TLSHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    ASSERT_FALSE( four_tuples.empty() );
    auto four_tuple = *four_tuples.begin();
    auto handshake_opt = ntk::get_handshake( packet_data );
    ASSERT_TRUE( handshake_opt ) << "No TCP Handshake found" << std::endl;
    auto& handshake = handshake_opt.value();
    ASSERT_EQ( handshake.syn, packet_data[ 0 /* index of syn in tls_handshake */ ] );
    ASSERT_EQ( handshake.syn_ack, packet_data[ 1 /* index of synack in tls_handshake */ ] );
    ASSERT_EQ( handshake.ack, packet_data[ 2 /* index of syn in tls_handshake */ ] );
}