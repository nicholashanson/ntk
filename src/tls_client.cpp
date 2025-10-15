#include <tls_client.hpp>

namespace ntk {

	void base_tls_client::process_tls_data() {
		if ( m_state == tls_state::client_hello_sent ) {
            handle_server_hello();
		}
		if ( m_state == tls_state::handshake_complete ) {
			process_application_record();
		} 
	}

    void base_tls_client::handle_incomplete_record() {
        std::size_t payload_size_before = m_incomplete_record.value().record.payload.size();
        auto record_variant = append_to_incomplete_record( m_incomplete_record.value(), m_buffer );
        if ( std::holds_alternative<tls_record>( record_variant ) ) {
            std::size_t payload_size_after = std::get<tls_record>( record_variant ).payload.size();
            handle_record( std::get<tls_record>( record_variant ) );
            std::size_t bytes_consumed = payload_size_after - payload_size_before;
            m_buffer.erase( m_buffer.begin(), m_buffer.begin() + bytes_consumed );
            m_incomplete_record.reset();
        } else {
            m_incomplete_record.value().record.payload.insert( m_incomplete_record.value().record.payload.end(), 
                                                               m_buffer.begin(), m_buffer.end() );
            m_buffer.clear();
        }
    }

    void base_tls_client::handle_complete_record() {
        auto split_result = split_tls_records( m_buffer );
        if ( !split_result ) {
            return;
        } else {
            auto [ records, offset_reached ] = split_result.value();
            if ( records.empty() ) {
                auto empty_record_result = get_empty_tls_record_from_payload( m_buffer );
                if ( !empty_record_result ) {
                    return;
                }
                auto record_header = get_tls_record_header_from_payload( m_buffer ).value();
                empty_record_result.value().payload.assign( m_buffer.begin() + constants::record_header_len, m_buffer.end() );
                m_incomplete_record = incomplete_tls_record {
                    empty_record_result.value(),
                    record_header.payload_length
                };
                m_buffer.clear(); 
            } else {
                for ( std::size_t i = 0; i < records.size(); ++i ) {
                    handle_record( records[ i ] );
                }
                m_buffer.erase( m_buffer.begin(), m_buffer.begin() + offset_reached );
            }
        }
    } 

	void base_tls_client::process_application_record() {
		while ( !m_buffer.empty() ) {
            if ( m_incomplete_record ) {
                handle_incomplete_record();
            } else {
                handle_complete_record();
            }
        }
	}

    void base_tls_client::handle_record( tls_record& rec ) {
        return;
    } 

    void base_tls_client::handle_server_hello() {
        auto record_result = get_tls_record_from_payload( m_buffer );
        if ( !record_result ) {
            return;
        }
        auto& server_hello_record = record_result.value();
        auto server_hello_result = get_server_hello_bytes( server_hello_record );
        if ( !server_hello_result ) {
            return;
        }
        auto& server_hello_bytes = server_hello_result.value(); 
        auto ctx_result = get_client_tls_context( m_client_hello_result, server_hello_bytes );
        if ( !ctx_result ) {
            return;
        }
        m_context = ctx_result.value();
    }

	// ===================================================
    //  Base TLS CLient Friend Helper :: Get Server State
    // ===================================================

    base_tls_client::tls_state base_tls_client_friend_helper::get_server_state( const base_tls_client& c ) {
    	return c.m_state;
    }

	// ===================================================
    //  Base TLS CLient Friend Helper :: Get Server State
    // ===================================================

    void base_tls_client_friend_helper::set_server_state( base_tls_client& c, base_tls_client::tls_state state ) {
    	c.m_state = state;
    }

    // ======================================================
    //  Base TLS CLient Friend Helper :: Set Internal Buffer
    // ======================================================

    void base_tls_client_friend_helper::set_internal_buffer( base_tls_client& c, std::span<const uint8_t> buffer ) {
    	c.m_buffer = { buffer.begin(), buffer.end() };
    }

    // ======================================================
    //  Base TLS CLient Friend Helper :: Set Internal Buffer
    // ======================================================

    std::vector<uint8_t> base_tls_client_friend_helper::get_internal_buffer( base_tls_client& c ) {
    	return c.m_buffer;
    }

    // ===================================================
    //  Base TLS CLient Friend Helper :: Process TLS Data
    // ===================================================

    void base_tls_client_friend_helper::process_tls_data( base_tls_client& c ) {
    	c.process_tls_data();
    }

    // ========================================================
    //  Base TLS CLient Friend Helper :: Get Incomplete Record
    // ========================================================

    std::optional<incomplete_tls_record> base_tls_client_friend_helper::get_incomplete_record( const base_tls_client& c ) {
        return c.m_incomplete_record;
    }

    // ==================================================
    //  Base TLS CLient Friend Helper :: Get TLS Context 
    // ==================================================

    std::optional<tls_context> base_tls_client_friend_helper::get_tls_context( const base_tls_client& c ) {
        return c.m_context;
    }

    // ==========================================================
    //  Base TLS CLient Friend Helper :: Set Client Hello Result 
    // ==========================================================

    void base_tls_client_friend_helper::set_client_hello_result( base_tls_client& c, const client_hello_result& c_hello_result ) {
        c.m_client_hello_result = c_hello_result;
    }

} // namespace ntk




