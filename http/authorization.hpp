#pragma once

#include <string>
#include <boost/beast/core/detail/base64.hpp>

namespace elx::http::authorization
{
    struct auth
    {
        [[nodiscard]] virtual std::string to_string() const
        {
            return { };
        }

        [[nodiscard]] bool is_empty() const {
            return to_string().empty();
        }
    };

    struct basic_string :
        auth
    {
        std::string string;

        basic_string()
        {
        }

        basic_string(const std::string& str) :
            string(str)
        {
        }

        basic_string(std::string&& str) :
            string(std::move(str))
        {
        }

        [[nodiscard]] std::string to_string() const override
        {
            return string;
        }
    };

    struct basic_auth :
        auth
    {
        std::string username;
        std::string password;

        [[nodiscard]] std::string to_string() const override
        {
            const std::string to_base64 = username + ":" + password;
            std::string base64;
            base64.resize(boost::beast::detail::base64::encoded_size(to_base64.size()));
            boost::beast::detail::base64::encode(base64.data(), to_base64.data(), to_base64.length());

            return "Authorization: Basic " + base64;
        }
    };

    struct bearer :
        auth
    {
        std::string bearer;

        [[nodiscard]] std::string to_string() const override
        {
            return "Authorization: Bearer " + bearer;
        }
    };
}
