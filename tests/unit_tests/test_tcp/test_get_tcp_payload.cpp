#include <gtest/gtest.h>

#include <pcap.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetTcpPayload ) {
    auto payload_result = ntk::get_tcp_payload( test::http_get_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
    auto& payload = *payload_result.value();
    ASSERT_EQ( payload.size(), 354 );
}

TEST( UnitTest, GetTcpPayload_TlsHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& client_hello_packet = packet_data[ 3 ];
    auto payload_result = ntk::get_tcp_payload( client_hello_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
    auto& payload = *payload_result.value();
    ASSERT_EQ( payload.size(), 329 );
}
