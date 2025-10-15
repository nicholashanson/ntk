#ifndef TLS_CLIENT_HPP
#define TLS_CLIENT_HPP

#include <tls.hpp>

namespace ntk {

	// =================
    //  Base TLS CLient 
    // =================

	class base_tls_client {
		public:
			enum class tls_state {
		        disconnected,
		        connecting,
		        client_hello_sent,
		        server_hello_recieved,
		        handshake_complete,
		        request_sent,
		        connected
		    };  
			base_tls_client() 
			: m_state( tls_state::disconnected ) {
				generate_default_client_config();
    			auto config_result = ntk::load_client_config();
    			if ( !config_result ) {
        			std::cout << "Failed to load client config: " << config_result.error() << std::endl;
    			}
    			m_config = config_result.value();
			}
		protected:
			void process_tls_data();
		private:  
			std::optional<incomplete_tls_record> m_incomplete_record;
			void process_application_record();
			void handle_incomplete_record();
			void handle_complete_record();
			void handle_record( tls_record& rec );
			void handle_server_hello();
		protected:
			tls_state m_state;
			std::string m_config;
			std::vector<uint8_t> m_buffer;
			client_hello_result m_client_hello_result;
		private:
			tls_context m_context;
			friend class base_tls_client_friend_helper;
	};

	// ===============================
    //  Base TLS CLient Friend Helper 
    // ===============================

    class base_tls_client_friend_helper {
    	public:
	    	static void set_server_state( base_tls_client& c, const base_tls_client::tls_state state );
	    	static base_tls_client::tls_state get_server_state( const base_tls_client& c );
	    	static void set_internal_buffer( base_tls_client& c, std::span<const uint8_t> buffer );
	    	static std::vector<uint8_t> get_internal_buffer( base_tls_client& c );
	    	static void process_tls_data( base_tls_client& c );
	    	static std::optional<incomplete_tls_record> get_incomplete_record( const base_tls_client& c );
	    	static std::optional<tls_context> get_tls_context( const base_tls_client& c );
	    	static void set_client_hello_result( base_tls_client& c, const client_hello_result& c_hello_result );
    };

} // namespace ntk

#endif