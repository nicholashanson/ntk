#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest_, GetEndOfHandshake ) {
    std::cout << "here" << std::endl;
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    std::cout << "here" << std::endl;
    std::cout << "here" << std::endl;
    auto four_tuples = ntk::get_four_tuples( packet_data );
    std::cout << "here" << std::endl;
    auto four_tuple = *four_tuples.begin();
    auto handshake = *ntk::get_handshake( four_tuple, packet_data );

    auto end_of_handshake_ptr = ntk::get_end_of_handshake( packet_data, handshake );
    auto& end_of_handshake = packet_data[ 2 ];

    ASSERT_NE( end_of_handshake_ptr, nullptr );
    ASSERT_EQ( *end_of_handshake_ptr, end_of_handshake );
}