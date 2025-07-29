#include <https.hpp>

namespace ntk {

	bool https_live_stream::feed( const std::vector<uint8_t>& packet ) {
		if ( !is_same_connection( packet, m_four ) ) return false;
		return tls_live_stream::feed( packet );
	}

	incomplete_request_response https_live_stream_friend_helper::get_incomplete_request_response( const https_live_stream& h ) {
		return h.m_incomplete_request_response;
	}

} // namespace ntk