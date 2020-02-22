#include <iostream>
#include <string>
#include <boost/asio/io_context.hpp>
#include "http/client.hpp"

int main(int argc, char** argv)
{
    // Check command line arguments.
    if(argc != 4 && argc != 5)
    {
        std::cerr <<
                  "Usage: http-client-sync-ssl <host> <port> <target>\n" <<
                  "Example:\n" <<
                  "    http-client-sync-ssl jsonplaceholder.typicode.com 80 /\n" <<
                  "    http-client-sync-ssl jsonplaceholder.typicode.com 443 /\n";
        return EXIT_FAILURE;
    }
    auto const host = argv[1];
    uint16_t const port = static_cast<uint16_t>(std::stoi(argv[2]));
    auto const target = argv[3];

    try {
        boost::asio::io_context io_ctx;
        boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tlsv12_client);
        ssl_ctx.set_default_verify_paths();
        ssl_ctx.set_verify_mode(boost::asio::ssl::verify_none);
        /*
         * todo: configure the ssl context here
         */


        elx::http::client::request req = {
            .host = host,
            .port = port,
            .target = target,
            .http_version = 11,
            .encryption = (port == 443 ? elx::http::client::request::encryption::tls : elx::http::client::request::encryption::none),
        };

        elx::http::client client(io_ctx, ssl_ctx);
        auto response = client.synchronous_get(req);

        std::cout << "response = " << response.body_string() << std::endl;

    }
    catch(std::exception const& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}