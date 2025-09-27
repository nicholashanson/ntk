#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>
#include <spmc_queue.hpp>

#include <test_constants.hpp>

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
        live_stream_session.feed_packet( packet );
    }
    ASSERT_EQ( live_stream_session.number_of_completed_transfers(), transfer_data.size() );
}