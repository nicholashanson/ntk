#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsTlsPayload ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& packet = packet_data[ 3 ];
    auto payload_result = ntk::get_tcp_payload( packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    EXPECT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
    auto& payload = *payload_result.value();
    auto result = ntk::is_tls_payload( payload );
    ASSERT_TRUE( result ) << result.error() << std::endl; 
    ASSERT_TRUE( result.value() );
}