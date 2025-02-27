#pragma once

#include <stdexcept>
#include <string>

namespace wallet {

class BalanceError : public std::runtime_error {
public:
    enum class ErrorType {
        Base58DecodeError,
        InvalidKeyFormat,
        DerivationError,
        RPCError,
        MissingCodeCantRun,
        InvalidBlockData
    };

    BalanceError(ErrorType type, const std::string& message = "")
        : std::runtime_error(message.empty() ? "Balance error" : message)
        , type_(type)
    {}

    ErrorType type() const { return type_; }

private:
    ErrorType type_;
};

} // namespace wallet  