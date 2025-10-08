#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetEndOfHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    ASSERT_FALSE( four_tuples.empty() );
    auto four_tuple = *four_tuples.begin();
    auto handshake_opt = ntk::get_handshake( four_tuple, packet_data );
    ASSERT_TRUE( handshake_opt ) << "TCP Handshake not found" << std::endl;
    auto end_of_handshake_ptr = ntk::get_end_of_handshake( packet_data, handshake_opt.value() );
    ASSERT_NE( end_of_handshake_ptr, nullptr ) << "End of Handshake points to NULL";
    auto* end_of_handshake = &packet_data[ 2 ];
    ASSERT_EQ( end_of_handshake_ptr, end_of_handshake );
}