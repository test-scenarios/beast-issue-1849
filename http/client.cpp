#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/erase.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include "client.hpp"
#include "client_transport.hpp"

using namespace elx::http;

client::client(boost::asio::io_context& ioc, boost::asio::ssl::context& ssl_ctx) :
    m_io_ctx(ioc),
    m_ssl_ctx(ssl_ctx),
    m_resolver(boost::asio::make_strand(ioc))
{
}

std::string client::sanitize_host(const std::string& host)
{
    if (boost::algorithm::starts_with(host, "https://"))
        return boost::algorithm::erase_first_copy(host,"https://");

    if (boost::algorithm::starts_with(host, "http://"))
        return boost::algorithm::erase_first_copy(host,"http://");

    return host;
}

enum client::request::encryption client::determine_encryption(const std::string& host)
{
    if (boost::algorithm::starts_with(host, "https://"))
        return client::request::encryption::tls;

    return client::request::encryption::none;
}

client::response client::synchronous_get(const request& req)
{
    namespace http = boost::beast::http;

    // Setup encryption
    switch (req.encryption) {
        case request::encryption::none:
            m_transport = client_transport::construct_tcp(m_io_ctx);
            break;

        case request::encryption::tls:
            m_transport = client_transport::construct_tls(m_io_ctx, m_ssl_ctx);
            break;
    }

    // Sanity check
    if (not m_transport)
        return { };

    // Look up the domain name
    auto const results = m_resolver.resolve(req.host, std::to_string(req.port));

    // Make the connection on any of the endpoints discovered by resolve
    m_transport.connect(results);

    // Perform handshake
    m_transport.handshake(req.host);

    // Set up an HTTP GET request message
    http::request<boost::beast::http::string_body> beast_req;
    beast_req.set(http::field::host, req.host);
    beast_req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    if (not req.auth.is_empty())
        beast_req.set(http::field::authorization, req.auth.to_string());
    beast_req.method(http::verb::get);
    beast_req.version(req.http_version);
    beast_req.target(req.target);

    // Send the HTTP beast_request to the remote host
    m_transport.write(beast_req);

    // Declare a container to hold the response
    response res;

    // Receive the HTTP response
    boost::beast::error_code ec;
    m_transport.read(res.raw, ec);
    if (ec) {
        throw boost::beast::system_error{ec};
    }

    // Gracefully close the socket
    m_transport.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);

    // not_connected happens sometimes
    // so don't bother reporting it.
    //
    if(ec && ec != boost::beast::errc::not_connected)
        throw boost::beast::system_error{ec};

    // If we get here then the connection is closed gracefully

    return res;
}