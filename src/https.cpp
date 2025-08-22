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
					return true;
				}
			}
			if ( is_http_response( m_decrypted_record.value().payload ) && m_expected_data ) {
				auto split_result = split_http_payload( m_decrypted_record.value().payload );
				auto split_http_message = *split_result;
				auto& body = split_http_message.body;
				if ( !m_incomplete_request_response.response ) {
					m_incomplete_request_response.response.emplace();
					m_incomplete_request_response.response->body = body;
					return true;
				} else {
					auto& existing_body = m_incomplete_request_response.response->body;
					existing_body.insert( existing_body.end(), body.begin(), body.end() );
					return true;
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