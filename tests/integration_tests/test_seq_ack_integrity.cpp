#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( IntegrationTest, SeqAckIntegrity ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tls_over_tcp tls_transfer( four_tuple );
    tls_transfer.load( packet_data );

    auto& client_traffic = ntk::tcp_transfer_friend_helper::client_traffic( tls_transfer );
    auto& server_traffic = ntk::tcp_transfer_friend_helper::server_traffic( tls_transfer );
    auto& client_acks = ntk::tcp_transfer_friend_helper::client_acks( tls_transfer );
    auto& server_acks = ntk::tcp_transfer_friend_helper::server_acks( tls_transfer );

    for ( auto& server_packet : server_traffic ) {
        size_t payload_length = ntk::get_tcp_payload( server_packet.data() ).size();
        ntk::tcp_header server_tcp_header = ntk::get_parsed_tcp_header( server_packet.data() );
        uint32_t expected_ack = server_tcp_header.seq_number + static_cast<uint32_t>( payload_length );

        bool found = std::any_of( client_acks.begin(), client_acks.end(),
            [&]( const std::vector<uint8_t>& client_packet ) {
                ntk::tcp_header client_tcp_header = ntk::get_parsed_tcp_header( client_packet.data() );
                return client_tcp_header.ack_number == expected_ack;
        });

        ASSERT_TRUE( found );
    }
}