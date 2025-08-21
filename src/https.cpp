#include <https.hpp>

namespace ntk {

	bool https_live_stream::feed( const std::vector<uint8_t>& packet ) {
		if ( !is_same_connection( packet, m_four ) ) return false;
		bool result = tls_live_stream::feed( packet );
		if ( m_decrypted_record ) {
			if ( is_http_request( m_decrypted_record.value().payload ) ) {
				m_incomplete_request_response.request = *get_http_request( m_decrypted_record.value().payload );
				if ( is_request_for<file_extension::M3U8>( m_incomplete_request_response.request.value() ) ) {
					m_expected_data = mime_type::VIDEO_MP2T;
				}
			}
		}
		return result;
	}

	incomplete_request_response https_live_stream_friend_helper::get_incomplete_request_response( const https_live_stream& h ) {
		return h.m_incomplete_request_response;
	}

	std::optional<mime_type> https_live_stream_friend_helper::expected_data( const https_live_stream& h ) {
		return h.m_expected_data;
	}

} // namespace ntk