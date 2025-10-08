#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( IntegrationTest, DistanceFromEndOfHandshakeToStartOfTermination ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    ASSERT_FALSE( four_tuples.empty() );
    auto four_tuple = *four_tuples.begin();
    auto termination_result = ntk::get_termination( four_tuple, packet_data );
    ASSERT_TRUE( termination_result ) << "No Termination found" << std::endl; 
    auto start_of_termination_ptr = ntk::get_start_of_termination( packet_data, termination_result.value() );
    auto handshake_result = ntk::get_handshake( four_tuple, packet_data );
    ASSERT_TRUE( handshake_result ) << "No Handshake found" << std::endl;
    auto end_of_handshake_ptr = ntk::get_end_of_handshake( packet_data, handshake_result.value() );
    auto size = static_cast<std::size_t>( start_of_termination_ptr - end_of_handshake_ptr );
    ASSERT_EQ( size, 15 );
}