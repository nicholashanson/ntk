#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>
#include <spmc_queue.hpp>

#include <test_constants.hpp>

TEST( IntegrationTest, TcpLiveStreamTcpLiveStreamSession ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    ASSERT_FALSE( packet_data.empty() );
    ntk::tcp_live_stream_session live_stream_session;
    for ( auto& packet : packet_data ) {
        live_stream_session.feed_packet( packet );
    }
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    ntk::tcp_live_stream expected_stream( four_tuple );
    for ( auto& packet : packet_data ) {
        expected_stream.feed( packet );
        if ( expected_stream.is_complete() ) break;
    }
    auto& four = ntk::tcp_live_stream_friend_helper::four( expected_stream );
    auto& actual_stream = ntk::tcp_live_stream_session_friend_helper::get_live_stream( live_stream_session, four );
    ASSERT_EQ( expected_stream, actual_stream );
}

TEST( IntegrationTest, TcpLiveStreamTcpLiveStreamSession_Checkerboard ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    ASSERT_FALSE( packet_data.empty() );
    ntk::tcp_live_stream_session live_stream_session;
    for ( auto& packet : packet_data ) {
        live_stream_session.feed_packet( packet );
    }
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    ntk::tcp_live_stream expected_stream( four_tuple );
    for ( auto& packet : packet_data ) {
        expected_stream.feed( packet );
        if ( expected_stream.is_complete() ) break;
    }
    auto& four = ntk::tcp_live_stream_friend_helper::four( expected_stream );
    auto& actual_stream = ntk::tcp_live_stream_session_friend_helper::get_live_stream( live_stream_session, four );
    ASSERT_EQ( expected_stream, actual_stream );
}

TEST( IntegrationTest, TcpLiveStreamTcpLiveStreamSession_MultipleFilesConcatenated  ) {
    std::vector<std::string> files = {
        test::packet_data_files[ "checkerboard" ],
        test::packet_data_files[ "tiny_cross" ],
    };
    std::vector<ntk::session> transfer_data;
    for ( auto& file : files ) {
        auto packet_data = ntk::read_packets_from_file( file );
        transfer_data.push_back( packet_data );   
    }
    ntk::session combined_packets;
    for ( auto& transfer : transfer_data ) {
        combined_packets.insert( combined_packets.end(), transfer.begin(), transfer.end() );
    }
    ntk::tcp_live_stream_session live_stream_session;
    for ( auto& packet : combined_packets ) {
        live_stream_session.feed_packet( packet );
    }
    std::vector<ntk::tcp_live_stream> expected_streams;
    for ( auto& transfer : transfer_data ) {
        auto four_tuples = ntk::get_four_tuples( transfer );
        auto four_tuple = *four_tuples.begin();
        ntk::tcp_live_stream live_stream( four_tuple );
        for ( auto& packet : transfer ) {
            live_stream.feed( packet );
            if ( live_stream.is_complete() ) break;
        }
        ASSERT_TRUE( live_stream.is_complete() );
        expected_streams.push_back( live_stream ); 
    }
    for ( auto& expected_stream : expected_streams ) {
        auto& four = ntk::tcp_live_stream_friend_helper::four( expected_stream );
        auto& actual_stream = ntk::tcp_live_stream_session_friend_helper::get_live_stream( live_stream_session, four );
        ASSERT_EQ( expected_stream, actual_stream );
    } 
}

