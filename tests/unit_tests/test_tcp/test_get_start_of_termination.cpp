#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTes, GetStartOfTermination_TinyCross ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ]  );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_termination = *ntk::get_termination( four_tuple, packet_data );
    auto start_of_termination_ptr = ntk::get_start_of_termination( packet_data, tcp_termination );
    ASSERT_NE( start_of_termination_ptr, nullptr );
}

TEST( UnitTest, GetStartOfTermination_TLSHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ]  );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    ASSERT_FALSE( four_tuples.empty() );
    auto four_tuple = *four_tuples.begin();
    auto termination_result = ntk::get_termination( four_tuple, packet_data );
    ASSERT_TRUE( termination_result ) << "No TCP Termination found" << std::endl;
    ASSERT_TRUE( std::holds_alternative<ntk::rst>( termination_result.value().closing_sequence ) );
    auto termination_header = *ntk::get_parsed_tcp_header_from_ethernet( std::get<ntk::rst>( termination_result.value().closing_sequence ) );
    auto& termination_start = packet_data[ 17 ];
    auto start_of_termination_ptr = ntk::get_start_of_termination( packet_data, termination_result.value() );
    ASSERT_NE( start_of_termination_ptr, nullptr );
    ASSERT_EQ( *start_of_termination_ptr, termination_start );
    ASSERT_EQ( static_cast<int>( termination_header.seq_number ), 1441872756 );
}