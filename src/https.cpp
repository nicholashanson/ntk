#include <https.hpp>

namespace ntk {

	// ===========================
    //  HTTPS Live Stream :: Feed
    // ===========================

	std::expected<bool,std::string> https_live_stream::feed( std::span<const uint8_t> packet ) {
		m_name_of_written_file = std::nullopt;
		m_is_complete = false;
		if ( !is_same_connection( packet, m_four ) ) return false;
		auto feed_result = tls_live_stream::feed( packet );
		if ( !feed_result ) {
			return std::unexpected( feed_result.error() );
		}
		if ( m_decrypted_records ) {
			if ( m_decrypted_records.value().size() == 1 ) {
				auto single_record_opt = handle_single_record();
				if ( single_record_opt ) {
					return single_record_opt.value();
				}
			}
			if ( m_incomplete_request_response.response ) {
				return handle_multiple_records();
			}
		}
		return feed_result.value();
	}

	// ===========================================
    //  HTTPS Live Stream :: Handle Single Record
    // ===========================================

	std::optional<bool> https_live_stream::handle_single_record() {
		auto& decrypted_record = m_decrypted_records->front();
		if ( is_http_request( decrypted_record.payload ) ) {
			return handle_http_request();
		}
		if ( is_http_response( decrypted_record.payload ) ) {
			return handle_http_response();
		}
		return std::nullopt;
	}

	// ==========================================
    //  HTTPS Live Stream :: Handle HTTP Request
    // ==========================================

	bool https_live_stream::handle_http_request() {
		auto& decrypted_record = m_decrypted_records->front();
		m_incomplete_request_response.request = *get_http_request( decrypted_record.payload );
		if ( is_request_for<file_extension::m3u8>( m_incomplete_request_response.request.value() ) ) {
			m_expected_data = mime_type::video_mp2t;
			return true;
		}
		return false;
	}

	// ===========================================
    //  HTTPS Live Stream :: Handle HTTP Response
    // ===========================================

	bool https_live_stream::handle_http_response() {
		auto& decrypted_record = m_decrypted_records->front();
		auto split_result = split_http_payload( decrypted_record.payload );
		auto split_http_message = *split_result;
		auto headers = parse_http_headers( split_http_message.headers );
		auto body = std::move( split_http_message.body );
		body.pop_back();
		if ( headers[ "Content-Type" ] == "application/vnd.apple.mpegurl" ) { 
			return true;
		}
		m_incomplete_request_response.response.emplace();
		auto it = headers.find( "Content-Length" );
		if ( it != headers.end() ) {
			m_incomplete_request_response.response->content_length = static_cast<std::size_t>( std::stoull( it->second) );
		}
		m_incomplete_request_response.response->body.insert(
			m_incomplete_request_response.response->body.end(),
			body.begin(), body.end()
		);
		if ( m_incomplete_request_response.response->http_response_complete() ) {
			m_is_complete = true;
			if ( m_incomplete_request_response.response->content_length ) {
				m_name_of_written_file = write_to_file( m_incomplete_request_response.response.value().body, file_extension::ts );
			} else {
				auto decoded_body = decode_chunked_http_body( m_incomplete_request_response.response.value().body );
				m_name_of_written_file = write_to_file( decoded_body, file_extension::ts );
			}
			m_incomplete_request_response.reset();
		}
		return true;
	}

	// ==============================================
    //  HTTPS Live Stream :: Handle Multiple Records
    // ==============================================

	bool https_live_stream::handle_multiple_records() {
		for ( auto& decrypted_record : m_decrypted_records.value() ) {
			auto body = decrypted_record.payload;
			body.pop_back();
			m_incomplete_request_response.response->body.insert(
				m_incomplete_request_response.response->body.end(),
				body.begin(), body.end()
			);
			if ( m_incomplete_request_response.response->http_response_complete() ) {
				m_is_complete = true;
				if ( m_incomplete_request_response.response->content_length ) {
					m_name_of_written_file = write_to_file( m_incomplete_request_response.response.value().body, file_extension::ts );
				} else {
					auto decoded_body = decode_chunked_http_body( m_incomplete_request_response.response.value().body );
					m_name_of_written_file = write_to_file( decoded_body, file_extension::ts );
				}
				m_incomplete_request_response.reset();
			}
		}
		return true;
	}

	// ======================================================
    //  HTTPS Live Stream Friend Helper :: Get Files Written
    // ======================================================

	std::optional<std::string> https_live_stream::get_file_written() {
		return m_name_of_written_file;
	}

	// ====================================================================
    //  HTTPS Live Stream Friend Helper :: Get Incomplete Request Response
    // ====================================================================

	incomplete_request_response https_live_stream_friend_helper::get_incomplete_request_response( const https_live_stream& h ) {
		return h.m_incomplete_request_response;
	}

	// ==================================================
    //  HTTPS Live Stream Friend Helper :: Expected Data
    // ==================================================

	std::optional<mime_type> https_live_stream_friend_helper::expected_data( const https_live_stream& h ) {
		return h.m_expected_data;
	}

	// =============================================================
    //  HTTPS Live Stream Friend Helper :: Name Files Written Files
    // =============================================================

	std::optional<std::string> https_live_stream_friend_helper::name_of_written_file( const https_live_stream& h ) {
		return h.m_name_of_written_file;
	}

	// ================================================
    //  HTTPS Live Stream Friend Helper :: Is Complete
    // ================================================

	bool https_live_stream_friend_helper::is_complete( const https_live_stream& h ) {
		return h.m_is_complete;
	}

	// ===========================
    //  HTTPS Live Stream Session 
    // ===========================

	https_live_stream_session::https_live_stream_session( std::string ssl_keys_log )
		: m_ssl_keys_log( ssl_keys_log ) {}


	// ===================================
    //  HTTPS Live Stream Session :: Feed 
    // ===================================

	bool https_live_stream_session::feed( std::span<const uint8_t> packet ) {
		auto four_result = get_four_from_ethernet( packet );
        if ( !four_result ) {
            //return std::unexpected( four_result.error() );
            return false;
        }

        if ( !m_four_tuples.contains( four_result.value() ) && !m_four_tuples.contains( flip_four( four_result.value() ) ) ) {
            m_four_tuples.insert( four_result.value() );
            m_live_streams.emplace_back( std::make_unique<https_live_stream>( four_result.value(), m_ssl_keys_log ) );
        } 

		for ( auto& stream : m_live_streams ) {
			auto feed_result = stream->feed( packet );
			if ( feed_result.value() ) {
				break;
			}
		}

		auto new_files_written = get_new_files_written();
		if ( new_files_written.empty() ) return true;
		if ( !m_files_written ) {
			m_files_written.emplace();
		}
		m_files_written->insert( m_files_written->end(), new_files_written.begin(), new_files_written.end() );
		return true;
	}

	// ====================================================
    //  HTTPS Live Stream Session :: Get New Files Written
    // ====================================================

	std::vector<std::string> https_live_stream_session::get_new_files_written() {
		std::vector<std::string> new_files;
		for ( auto& stream : m_live_streams ) {
			auto file_written_opt = stream->get_file_written();
			if ( file_written_opt ) {
				new_files.push_back( file_written_opt.value() ); 
			}
		}
		return new_files;
	}

	// ================================================
    //  HTTPS Live Stream Session :: Get Files Written
    // ================================================

	std::optional<std::vector<std::string>> https_live_stream_session::get_files_written() {
		return m_files_written;
	}

	// ============================================================
    //  HTTPS Live Stream Session Friend Helper :: Get Live Stream
    // ============================================================

	const std::unique_ptr<https_live_stream>& https_live_stream_session_friend_helper::get_live_stream( const https_live_stream_session& h, const four_tuple& four ) {
		return h.m_live_streams.front();
	}

	// =========================================================
    //  HTTPS Live Stream Session Friend Helper :: Live Streams
    // =========================================================

	const std::vector<std::unique_ptr<https_live_stream>>& https_live_stream_session_friend_helper::live_streams( const https_live_stream_session& h ) {
		return h.m_live_streams;
	}

	// ========================================================
    //  HTTPS Live Stream Session Friend Helper :: Four Tuples  
    // ========================================================
    
    const std::unordered_set<four_tuple>& https_live_stream_session_friend_helper::four_tuples( const https_live_stream_session& h ) {
    	return h.m_four_tuples;
    }

    // ==========================================================
    //  HTTPS Live Stream Session Friend Helper :: Files Written
    // ==========================================================

	std::optional<std::vector<std::string>> https_live_stream_session_friend_helper::files_written( const https_live_stream_session& h ) {
		return h.m_files_written;
	}

	// ==================================
    //  HTTPS Decryption Context :: Feed
    // ==================================

    std::expected<bool,std::string> https_decryption_context::feed( std::span<const uint8_t> packet ) {
    	auto feed_result = tls_decryption_context::feed( packet );
    	if ( !feed_result ) {
    		return std::unexpected( feed_result.error() );
    	}
    	while ( !m_task_queue.empty() ) {
    		auto task = std::move( m_task_queue.front() );
    		m_task_queue.pop();
    		if ( !m_incomplete_request_response ) {
    			auto decrypted_record = handle_decryption_task( task ); 
    			decrypted_record.payload.pop_back();
    			if ( is_http_response( decrypted_record.payload ) ) {
    				auto parse_result = get_http_response( decrypted_record.payload );
    				if ( !parse_result ) {
    					return std::unexpected( "Failed to parse response" );
    				}
    				auto split_result = split_http_payload( decrypted_record.payload );
    				auto split_http_message = *split_result;
					auto headers = parse_http_headers( split_http_message.headers );
					if ( headers[ "Content-Type" ] == "application/vnd.apple.mpegurl" ) {
						continue;
					}
					auto it = headers.find( "Content-Length" );
					if ( it != headers.end() ) {
						m_incomplete_request_response->response->content_length = static_cast<std::size_t>( std::stoull( it->second) );
						m_expected_bytes = m_incomplete_request_response->response->content_length.value();
					}
					
    				m_incomplete_request_response.emplace();
    				m_incomplete_request_response->response.emplace();
    				m_incomplete_request_response->response->body = parse_result.value().body;
    				m_recieved_bytes = m_incomplete_request_response->response->body.size();
    				continue;
    			}
    		}
    		else {
    			m_recieved_bytes += task.record.payload.size() - 16 /* tag bytes */ - 1;
    			decrypt_record_asynchronously( std::move( task ) );
    			if ( m_recieved_bytes == m_expected_bytes ) {
    				wait_for_all();
    				finalize_response();
    				m_expected_bytes = 0;
    				m_recieved_bytes = 0;
    				return true;	
    			}
    		}
    	}
    	return feed_result.value();
    }

    // ===============================================
    //  HTTPS Decryption Context :: Finalize Response
    // ===============================================

    void https_decryption_context::finalize_response() {
    	for ( auto& [ seq, record ] : m_decrypted_records ) {
        	auto& payload = record.payload;
        	payload.pop_back();
        	m_incomplete_request_response->response->body.insert(
            	m_incomplete_request_response->response->body.end(),
            	payload.begin(),
            	payload.end()
        	);
    	}
    	m_decrypted_records.clear();
	}

	// ==========================================================================
    //  HTTPS Decryption Context Friend Helper :: Get Incomplete Request Respone
    // ==========================================================================

    std::optional<incomplete_request_response> https_decryption_context_friend_helper::get_incomplete_request_response( const https_decryption_context& h ) {
    	return h.m_incomplete_request_response;
    }

    // ==============================================================
    //  HTTPS Decryption Context Friend Helper :: Get Expected Bytes
    // ==============================================================

    std::size_t https_decryption_context_friend_helper::get_expected_bytes( const https_decryption_context& h ) {
    	return h.m_expected_bytes;
    }

    // ==============================================================
    //  HTTPS Decryption Context Friend Helper :: Get Recieved Bytes
    // ==============================================================

    std::size_t https_decryption_context_friend_helper::get_recieved_bytes( const https_decryption_context& h ) {
    	return h.m_recieved_bytes;
    }

} // namespace ntk>