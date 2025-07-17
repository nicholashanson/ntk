#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <io.hpp>
#include <test_constants.hpp>

// ==============================
//         Traffic Size
// ==============================

TEST( UnitTest, TcpLiveStream_Traffic_Size ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four_tuple );

    for ( auto& packet : packet_data ) {
        live_stream.feed( packet );
        if ( live_stream.is_complete() ) break;
    }

    auto& traffic = ntk::tcp_live_stream_friend_helper::traffic( live_stream );

    ASSERT_EQ( traffic.size(), 22 );
}

// ==============================
//        Termination Feed
// ==============================

TEST( UnitTest, TcpLiveStream_TerminationFeed_TinyCross ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four_tuple );

    for ( auto& packet : packet_data ) {
        live_stream.feed( packet );
        if ( live_stream.is_complete() ) break;
    }

    auto& termination_feed = ntk::tcp_live_stream_friend_helper::termination_feed( live_stream );
    auto& closing_sequence = std::get<ntk::fin_ack_fin_ack>( termination_feed.m_termination.closing_sequence );

    ASSERT_EQ( closing_sequence.initiator_fin, packet_data[ to_index( test::tiny_cross::INITIATOR_FIN ) ] );
    ASSERT_EQ( closing_sequence.responder_ack, packet_data[ to_index( test::tiny_cross::RESPONDER_ACK ) ] );
    ASSERT_EQ( closing_sequence.responder_fin, packet_data[ to_index( test::tiny_cross::RESPONDER_FIN ) ] );
    ASSERT_EQ( closing_sequence.initiator_ack, packet_data[ to_index( test::tiny_cross::INITIATOR_ACK ) ] );
}

TEST( UnitTest, TcpLiveStream_TerminationFeed_Checkerboard ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four_tuple );

    for ( auto& packet : packet_data ) {
        live_stream.feed( packet );
        if ( live_stream.is_complete() ) break;
    }

    auto& termination_feed = ntk::tcp_live_stream_friend_helper::termination_feed( live_stream );
    auto& closing_sequence = std::get<ntk::fin_ack_fin_ack>( termination_feed.m_termination.closing_sequence );

    ASSERT_EQ( closing_sequence.initiator_fin, packet_data[ 25 ] );
    ASSERT_EQ( closing_sequence.responder_ack, packet_data[ 28 ] );
    ASSERT_EQ( closing_sequence.responder_fin, packet_data[ 26 ] );
    ASSERT_EQ( closing_sequence.initiator_ack, packet_data[ 27 ] );
}

TEST( UnitTest, TcpLiveStream_HandshakeFeed_TinyCross ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four_tuple );

    for ( auto& packet : packet_data ) {
        live_stream.feed( packet );
        if ( live_stream.is_complete() ) break;
    }

    auto& handshake_feed = ntk::tcp_live_stream_friend_helper::handshake_feed( live_stream );

    ASSERT_EQ( handshake_feed.m_handshake.syn, packet_data[ to_index( test::tiny_cross::SYN ) ] );
    ASSERT_EQ( handshake_feed.m_handshake.syn_ack, packet_data[ to_index( test::tiny_cross::SYNACK ) ] );
    ASSERT_EQ( handshake_feed.m_handshake.ack, packet_data[ to_index( test::tiny_cross::ACK ) ] );
}

TEST( UnitTest, TcpLiveStream_HandshakeFeed_Checkerboard ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four_tuple );

    for ( auto& packet : packet_data ) {
        live_stream.feed( packet );
        if ( live_stream.is_complete() ) break;
    }

    auto& handshake_feed = ntk::tcp_live_stream_friend_helper::handshake_feed( live_stream );

    ASSERT_EQ( handshake_feed.m_handshake.syn, packet_data[ to_index( test::checkerboard::SYN ) ] );
    ASSERT_EQ( handshake_feed.m_handshake.syn_ack, packet_data[ to_index( test::checkerboard::SYNACK ) ] );
    ASSERT_EQ( handshake_feed.m_handshake.ack, packet_data[ to_index( test::checkerboard::ACK ) ] );
}

// ==============================
//          Is Complete
// ==============================

TEST( UnitTest, TcpLiveStream_IsComplete_TinyCross ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four_tuple );

    for ( auto& packet : packet_data ) {
        live_stream.feed( packet );
        if ( live_stream.is_complete() ) break;
    }

    ASSERT_TRUE( live_stream.is_complete() );
}

TEST( UnitTest, TcpLiveStream_IsComplete_Checkerboard ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four_tuple );

    for ( auto& packet : packet_data ) {
        live_stream.feed( packet );
        if ( live_stream.is_complete() ) break;
    }

    ASSERT_TRUE( live_stream.is_complete() );
}