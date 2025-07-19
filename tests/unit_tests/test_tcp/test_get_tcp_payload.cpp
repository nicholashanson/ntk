#include <gtest/gtest.h>

#include <pcap.h>

#include <span>
#include <cstdint>

#include <packet_listener.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetTcpPayload ) {
    auto http_payload = ntk::get_tcp_payload( test::http_get_packet );
    ASSERT_EQ( http_payload.size(), 354 );
}
TEST( UnitTest, GetTcpPayload_TlsHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& tls_client_hello = packet_data[ 3 ];
    auto client_helllo_record = ntk::get_tcp_payload( tls_client_hello );
    ASSERT_EQ( client_helllo_record.size(), 329 );
}
