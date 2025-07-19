#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <io.hpp>
#include <spmc_queue.hpp>
#include <test_constants.hpp>

TEST( IntegrationTest, LiveStreamAndLiveStreamSession_TinyCross ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );

    ntk::tcp_live_stream_session live_stream_session;
    for ( auto& packet : packet_data ) {
        live_stream_session.feed( packet );
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

TEST( IntegrationTest, LiveStreamAndLiveStreamSession_Checkerboard ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );

    ntk::tcp_live_stream_session live_stream_session;
    for ( auto& packet : packet_data ) {
        live_stream_session.feed( packet );
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

TEST( IntegrationTest, LiveStreamAndLiveStreamSession_MultipleFilesConcatenated  ) {
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
        live_stream_session.feed( packet );
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

TEST( UnitTest, LiveStreamAndLiveStreamSession_MultipleFilesInterleaved ) {
    std::vector<std::string> files = {
        test::packet_data_files[ "checkerboard" ],
        test::packet_data_files[ "tiny_cross" ],
    };

    std::vector<ntk::session> transfer_data;
    for ( auto& file : files ) {
        auto packet_data = ntk::read_packets_from_file( file );
        transfer_data.push_back( packet_data );   
    }

    std::size_t max_size = -std::numeric_limits<size_t>::max();
    for ( auto& transfer : transfer_data ) {
        if ( transfer.size() > max_size ) max_size = transfer.size();
    }

    ntk::session combined_packets;
    for ( std::size_t i = 0; i < max_size; ++i ) {
        for ( auto& transfer : transfer_data ) {
            if ( i < transfer.size() ) combined_packets.push_back( transfer[ i ] );
        }
    }

    ntk::tcp_live_stream_session live_stream_session;
    for ( auto& packet : combined_packets ) {
        live_stream_session.feed( packet );
    }
    ASSERT_EQ( live_stream_session.number_of_completed_transfers(), transfer_data.size() );
}