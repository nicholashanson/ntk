#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( IntegrationTest, TlsFilter ) {
    ntk::tls_filter filter;
    ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::tls_filter> offload_queue( filter );
    ntk::tcp_live_stream_session live_stream_session( &offload_queue ); 
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );

    ASSERT_TRUE( offload_queue.empty() ) ;

    for ( auto& packet : packet_data ) {
        live_stream_session.feed( packet );
    }

    ASSERT_TRUE( live_stream_session.number_of_completed_transfers() == 0 );
    ASSERT_TRUE( offload_queue.empty() );
}