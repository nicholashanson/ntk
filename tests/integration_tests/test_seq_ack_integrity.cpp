#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( IntegrationTest, SeqAckIntegrity ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    ASSERT_FALSE( four_tuples.empty() );
    auto four_tuple = *four_tuples.begin();
    ntk::tls_over_tcp tls_transfer( four_tuple );
    tls_transfer.load( packet_data );
    auto& client_traffic = ntk::tcp_transfer_friend_helper::client_traffic( tls_transfer );
    auto& server_traffic = ntk::tcp_transfer_friend_helper::server_traffic( tls_transfer );
    auto& client_acks = ntk::tcp_transfer_friend_helper::client_acks( tls_transfer );
    auto& server_acks = ntk::tcp_transfer_friend_helper::server_acks( tls_transfer );

    for ( auto& server_packet : server_traffic ) {
        auto payload_result = ntk::get_tcp_payload( server_packet );
        ASSERT_TRUE( payload_result ) << payload_result.error();
        auto& payload = *payload_result.value();
        auto server_tcp_header = *ntk::get_parsed_tcp_header_from_ethernet( server_packet );
        uint32_t expected_ack = server_tcp_header.seq_number + static_cast<uint32_t>( payload.size() );
        bool found = std::any_of( client_acks.begin(), client_acks.end(),
            [ & ] ( const auto& client_packet ) {
                auto header_result = ntk::get_parsed_tcp_header_from_ethernet( client_packet );
                EXPECT_TRUE( header_result ) << header_result.error();
                if ( !header_result ) return false;
                return header_result.value().ack_number == expected_ack;
        });
        ASSERT_TRUE( found );
    }
}