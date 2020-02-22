#pragma once

#include <boost/beast/http.hpp>
#include <boost/beast/core/buffers_to_string.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include "authorization.hpp"
#include "client_transport.hpp"

namespace http = boost::beast::http;

namespace elx::http
{
    class client
    {
    public:
        struct request
        {
            enum class encryption {
                none,
                tls
            };

            std::string host;
            uint16_t port;
            std::string target;
            uint8_t http_version = 11;
            authorization::auth auth;
            encryption encryption = encryption::none;
        };

        struct response
        {
            boost::beast::http::response<boost::beast::http::dynamic_body> raw;

            std::string body_string() const
            {
                return boost::beast::buffers_to_string(raw.body().data());
            }
        };

        // Construction
        explicit client(boost::asio::io_context& ioc,
            boost::asio::ssl::context& ssl_ctx);
        client(const client& other) = delete;
        client(client&& other) = delete;
        virtual ~client() = default;

        [[nodiscard]] static std::string sanitize_host(const std::string& host);
        [[nodiscard]] static enum request::encryption determine_encryption(const std::string& host);
        [[nodiscard]] response synchronous_get(const request& req);

    private:
        boost::asio::io_context& m_io_ctx;
        boost::asio::ssl::context& m_ssl_ctx;
        boost::asio::ip::tcp::resolver m_resolver;
        std::unique_ptr<client_transport> m_transport;

    };
}
