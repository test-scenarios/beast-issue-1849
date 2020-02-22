#pragma once

#include <boost/asio/ip/resolver_base.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/ssl.hpp>

namespace elx::http
{
    class client_transport
    {
    public:
        using response_type = boost::beast::http::response<boost::beast::http::dynamic_body>;

        [[nodiscard]] virtual boost::beast::tcp_stream& stream() = 0;

        void write(boost::beast::http::request<boost::beast::http::string_body>& request)
        {
            handle_write(request);
        }

        void read(response_type& response,
                  boost::beast::error_code& ec)
        {
            handle_read(response, ec);
        }

        virtual boost::beast::error_code set_hostname(const std::string& hostname) { return { }; }
        virtual void handshake() { }

        void connect(const boost::asio::ip::tcp::resolver::results_type results)
        {
            stream().connect(results);
        }

    private:
        virtual void handle_write(boost::beast::http::request<boost::beast::http::string_body>& request) = 0;
        virtual void handle_read(response_type& response,
                                 boost::beast::error_code& ec) = 0;

    protected:
        boost::beast::flat_buffer m_buffer;

    };

    class client_transport_plain :
        public client_transport
    {
    public:
        client_transport_plain(boost::asio::io_context& io_ctx) :
            m_stream(io_ctx)
        {
        }

        [[nodiscard]] boost::beast::tcp_stream& stream() override
        {
            return m_stream;
        }

    private:
        void handle_write(boost::beast::http::request<boost::beast::http::string_body>& request) override
        {
            boost::beast::http::
            write(m_stream, request);
        }

        void handle_read(response_type& response,
                         boost::beast::error_code& ec) override
        {
            boost::beast::http::
            read(m_stream, m_buffer, response, ec);
        }

    private:
        boost::beast::tcp_stream m_stream;
    };

    class client_transport_tls :
        public client_transport
    {
    public:
        client_transport_tls(boost::asio::io_context& io_ctx, boost::asio::ssl::context& ssl_ctx) :
            m_io_ctx(io_ctx),
            m_ssl_ctx(ssl_ctx),
            m_stream(io_ctx, ssl_ctx)
        {
        }

        [[nodiscard]] boost::beast::tcp_stream& stream() override
        {
            return m_stream.next_layer();
        }

        boost::beast::error_code set_hostname(const std::string& hostname) override
        {
            // Set SNI Hostname (many hosts need this to handshake successfully)
            if (not SSL_set_tlsext_host_name(m_stream.native_handle(), hostname.c_str())) {
                return boost::beast::error_code{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
            }

            return { };
        }

        void handshake() override
        {
            m_stream.handshake(boost::asio::ssl::stream_base::client);
        }

    private:
        void handle_write(boost::beast::http::request<boost::beast::http::string_body>& request) override
        {
            boost::beast::http::
            write(m_stream, request);
        }

        void handle_read(response_type& response,
                         boost::beast::error_code& ec) override
        {
            boost::beast::http::
            read(m_stream, m_buffer, response, ec);
        }

    private:
        boost::asio::io_context& m_io_ctx;
        boost::asio::ssl::context& m_ssl_ctx;
        boost::beast::ssl_stream<boost::beast::tcp_stream> m_stream;
    };
}
