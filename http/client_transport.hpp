#pragma once

#include <boost/asio/ip/resolver_base.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/ssl.hpp>

namespace elx::http
{
    // Customisation points for different stream types
    template < class Stream >
    void sync_connect(Stream &stream, const boost::asio::ip::tcp::resolver::results_type &results)
    {
        stream.connect(results);
    }

    template < class Underlying >
    void sync_connect(boost::beast::ssl_stream< Underlying > &            stream,
                      const boost::asio::ip::tcp::resolver::results_type &results)
    {
        sync_connect(stream.next_layer(), results);
    }

    template < class Stream >
    void sync_transport_handshake(Stream &stream, std::string const &hostname)
    {
        // no-op
    }

    template < class Underlying >
    void sync_transport_handshake(boost::beast::ssl_stream< Underlying > &stream, std::string const &hostname)
    {
        if (not SSL_set_tlsext_host_name(stream.native_handle(), hostname.c_str()))
            throw boost::beast::system_error(boost::beast::error_code { static_cast< int >(::ERR_get_error()),
                                                                        boost::asio::error::get_ssl_category() });
        stream.handshake(boost::asio::ssl::stream_base::client);
    }

    template < class Stream >
    void shutdown_stream(Stream &stream, boost::asio::ip::tcp::socket::shutdown_type type, boost::beast::error_code &ec)
    {
        stream.socket().shutdown(type, ec);
    }

    template < class Underlying >
    void shutdown_stream(boost::beast::ssl_stream< Underlying > &    stream,
                         boost::asio::ip::tcp::socket::shutdown_type type,
                         boost::beast::error_code &                  ec)
    {
        stream.shutdown(ec);
        shutdown_stream(stream.next_layer(), type, ec);
    }

    class client_transport
    {
      public:
        using response_type = boost::beast::http::response< boost::beast::http::dynamic_body >;
        using request_type  = boost::beast::http::request< boost::beast::http::string_body >;
        using buffer_type   = boost::beast::flat_buffer;

      private:
        // define the internal polymorphic concept
        struct concept
        {
            // virtual, designed to be owned by smart ptr
            concept()                = default;
            concept(concept const &) = delete;
            concept &operator=(concept const &) = delete;
            virtual ~concept()                  = default;

            // interface
            virtual void handle_connect(boost::asio::ip::tcp::resolver::results_type results)                   = 0;
            virtual void handle_write(boost::beast::http::request< boost::beast::http::string_body > & request) = 0;
            virtual void handle_read(response_type & response, boost::beast::error_code & ec)                   = 0;
            virtual void handle_handshake(const std::string &hostname)                                          = 0;
            virtual void handle_shutdown(boost::asio::ip::tcp::socket::shutdown_type type,
                                         boost::beast::error_code & ec)                                         = 0;

          protected:
            buffer_type buffer_;
        };

        // build models of the concept
        template < class Stream >
        struct model : concept
        {
            template < class... Args >
            explicit model(std::in_place_t, Args &&... args)
            : stream_(std::forward< Args >(args)...)
            {
            }

            void handle_connect(boost::asio::ip::tcp::resolver::results_type results) override
            {
                sync_connect(stream_, results);
            }

            void handle_write(request_type &request) { boost::beast::http::write(stream_, request); }

            void handle_read(response_type &response, boost::beast::error_code &ec) override
            {
                boost::beast::http::read(stream_, buffer_, response, ec);
            }

            virtual void handle_handshake(const std::string &hostname) override
            {
                return sync_transport_handshake(stream_, hostname);
            }

            void handle_shutdown(boost::asio::ip::tcp::socket::shutdown_type type,
                                 boost::beast::error_code &                  ec) override
            {
                shutdown_stream(stream_, type, ec);
            }

            Stream stream_;
        };

        using impl_type = std::unique_ptr< concept >;

      public:
        static client_transport construct_tcp(boost::asio::io_context &io_ctx)
        {
            using stream_type = boost::beast::tcp_stream;
            return client_transport(std::make_unique< model< stream_type > >(std::in_place, io_ctx));
        }

        static client_transport construct_tls(boost::asio::io_context &io_ctx, boost::asio::ssl::context &ssl_ctx)
        {
            using stream_type = boost::beast::ssl_stream< boost::beast::tcp_stream >;
            return client_transport(std::make_unique< model< stream_type > >(std::in_place, io_ctx, ssl_ctx));
        }

        explicit client_transport(impl_type impl = nullptr)
        : impl_(std::move(impl))
        {
        }

        client_transport(client_transport &&) = default;
        client_transport &operator=(client_transport &&) = default;

        void write(request_type &request) { impl_->handle_write(request); }

        void read(response_type &response, boost::beast::error_code &ec) { impl_->handle_read(response, ec); }

        void handshake(const std::string &hostname) { return impl_->handle_handshake(hostname); }

        void connect(const boost::asio::ip::tcp::resolver::results_type &results) { impl_->handle_connect(results); }

        void shutdown(boost::asio::ip::tcp::socket::shutdown_type type, boost::beast::error_code &ec)
        {
            impl_->handle_shutdown(type, ec);
        }

        operator bool() const { return impl_.get(); }

      private:
        std::unique_ptr< concept > impl_;
    };

}   // namespace elx::http
