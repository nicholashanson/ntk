#include <https.hpp>

namespace ntk {

	bool https_live_stream::feed( const std::vector<uint8_t>& packet ) {
		m_name_of_written_file = std::nullopt;
		if ( !is_same_connection( packet, m_four ) ) return false;
		bool result = tls_live_stream::feed( packet );
		if ( m_decrypted_records ) {
			if ( m_decrypted_records.value().size() == 1 ) {
				auto& decrypted_record = m_decrypted_records.value().front();
				if ( is_http_request( decrypted_record.payload ) ) {
					m_incomplete_request_response.request = *get_http_request( decrypted_record.payload );
					if ( is_request_for<file_extension::M3U8>( m_incomplete_request_response.request.value() ) ) {
						m_expected_data = mime_type::VIDEO_MP2T;
						return true;
					}
				}
				if ( is_http_response( decrypted_record.payload ) ) {
					auto split_result = split_http_payload( decrypted_record.payload );
					auto split_http_message = *split_result;
					auto headers = parse_http_headers( split_http_message.headers );
					auto body = std::move( split_http_message.body );
					body.pop_back();
					if ( headers[ "Content-Type" ] == "application/vnd.apple.mpegurl" ) { 
						return true;
					}
					m_incomplete_request_response.response.emplace();
					m_incomplete_request_response.response.value().content_length = static_cast<std::size_t>( std::stoull( headers[ "Content-Length" ] ) );
					m_incomplete_request_response.response.value().body.insert(
						m_incomplete_request_response.response.value().body.end(),
						body.begin(), body.end()
					);
					if ( m_incomplete_request_response.response->http_response_complete() ) {
						m_name_of_written_file = write_to_file( m_incomplete_request_response.response.value().body, file_extension::TS );
						m_incomplete_request_response.reset();
					}
					return true;
				}
			}
			if ( m_incomplete_request_response.response ) {
				for ( auto& decrypted_record : m_decrypted_records.value() ) {
					auto body = decrypted_record.payload;
					body.pop_back();
					m_incomplete_request_response.response.value().body.insert(
						m_incomplete_request_response.response.value().body.end(),
						body.begin(), body.end()
					);
					if ( m_incomplete_request_response.response->http_response_complete() ) {
						m_name_of_written_file = write_to_file( m_incomplete_request_response.response.value().body, file_extension::TS );
						m_incomplete_request_response.reset();
					}
				}
				return true;
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

	std::optional<std::string> https_live_stream_friend_helper::name_of_written_file( const https_live_stream& h ) {
		return h.m_name_of_written_file;
	}

} // namespace ntk