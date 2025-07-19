#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( IntegrationTest, DistanceFromEndOfHandshakeToStartOfTermination ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    auto termination = *ntk::get_termination( four_tuple, packet_data );
    auto start_of_termination_ptr = ntk::get_start_of_termination( packet_data, termination );

    auto handshake = *ntk::get_handshake( four_tuple, packet_data );
    auto end_of_handshake_ptr = ntk::get_end_of_handshake( packet_data, handshake );

    auto size = static_cast<size_t>( start_of_termination_ptr - end_of_handshake_ptr );
    ASSERT_EQ( size, 15 );
}