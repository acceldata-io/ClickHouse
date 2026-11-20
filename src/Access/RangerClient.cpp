#include <Access/RangerClient.h>
#include <Common/Exception.h>
#include <Common/logger_useful.h>
#include <IO/ReadBufferFromPocoSocket.h>
#include <IO/WriteBufferFromPocoSocket.h>
#include <IO/ReadHelpers.h>
#include <IO/WriteHelpers.h>
#include <Poco/Timespan.h>

namespace DB
{

namespace ErrorCodes
{
    extern const int BAD_ARGUMENTS;
    extern const int NETWORK_ERROR;
}

RangerClient::RangerClient(const Config & config_)
    : config(config_)
{
}

RangerClient::~RangerClient()
{
    std::lock_guard lock(mutex);
    socket.reset();
}

bool RangerClient::connectImpl()
{
    try
    {
        Poco::Net::SocketAddress address(config.host, config.port);
        auto new_socket = std::make_unique<Poco::Net::StreamSocket>();

        new_socket->connect(address, Poco::Timespan(config.connect_timeout_ms * 1000)); // microseconds
        new_socket->setReceiveTimeout(Poco::Timespan(config.receive_timeout_ms * 1000));
        new_socket->setSendTimeout(Poco::Timespan(config.send_timeout_ms * 1000));
        new_socket->setNoDelay(true); // TCP_NODELAY

        socket = std::move(new_socket);
        LOG_DEBUG(getLogger("RangerClient"), "Connected to Ranger agent at {}:{}", config.host, config.port);
        return true;
    }
    catch (const Poco::Exception & e)
    {
        LOG_WARNING(getLogger("RangerClient"), "Failed to connect to Ranger agent: {}", e.displayText());
        socket.reset();
        return false;
    }
}

bool RangerClient::reconnectImpl()
{
    socket.reset();
    return connectImpl();
}

bool RangerClient::sendRequestImpl(const String & request, String & response_out)
{
    if (!socket)
    {
        if (!connectImpl())
            return false;
    }

    try
    {
        // Write request
        WriteBufferFromPocoSocket out(*socket);
        writeString(request, out);
        writeChar('\n', out);
        out.next();
        out.finalize();

        // Read response (one line)
        ReadBufferFromPocoSocket in(*socket);
        readString(response_out, in, '\n');

        // Remove trailing newline if present
        if (!response_out.empty() && response_out.back() == '\n')
            response_out.pop_back();

        return true;
    }
    catch (const Poco::Exception & e)
    {
        LOG_WARNING(getLogger("RangerClient"), "Communication error with Ranger agent: {}", e.displayText());
        socket.reset();

        // Retry once
        if (connectImpl())
        {
            try
            {
                WriteBufferFromPocoSocket out(*socket);
                writeString(request, out);
                writeChar('\n', out);
                out.next();
                out.finalize();

                ReadBufferFromPocoSocket in(*socket);
                readString(response_out, in, '\n');

                if (!response_out.empty() && response_out.back() == '\n')
                    response_out.pop_back();

                return true;
            }
            catch (const Poco::Exception & retry_e)
            {
                LOG_WARNING(getLogger("RangerClient"), "Retry failed: {}", retry_e.displayText());
                socket.reset();
            }
        }

        return false;
    }
}

void RangerClient::sanitizeField(const String & field, const String & field_name)
{
    if (field.find('\t') != String::npos || field.find('\n') != String::npos)
    {
        throw Exception(ErrorCodes::BAD_ARGUMENTS,
            "Ranger: {} contains tab or newline (potential injection): '{}'",
            field_name, field);
    }
}

void RangerClient::logRequest(const String & request, const String & response, bool allowed)
{
    LOG_TRACE(getLogger("RangerClient"),
        "Ranger request: {} => response: {} ({})",
        request, response, allowed ? "ALLOW" : "DENY");
}

bool RangerClient::checkAccess(
    const String & user,
    const String & privileges,
    const String & database,
    const String & table,
    const String & column,
    String * reason_out)
{
    // Before READY, deny everything
    if (!isReady())
    {
        if (reason_out)
            *reason_out = "Ranger agent not ready";
        LOG_DEBUG(getLogger("RangerClient"), "Ranger agent not ready, denying request");
        return false;
    }

    // Sanitize inputs
    try
    {
        sanitizeField(user, "user");
        sanitizeField(privileges, "privileges");
        sanitizeField(database, "database");
        sanitizeField(table, "table");
        sanitizeField(column, "column");
    }
    catch (const Exception & e)
    {
        if (reason_out)
            *reason_out = e.message();
        LOG_WARNING(getLogger("RangerClient"), "Sanitization failed: {}", e.message());
        return false;
    }

    // Build request: CHECK\tuser\tprivileges\tdatabase\ttable\tcolumn
    String request = "CHECK\t" + user + "\t" + privileges + "\t" + database + "\t" + table + "\t" + column;

    std::lock_guard lock(mutex);

    String response;
    if (!sendRequestImpl(request, response))
    {
        if (reason_out)
            *reason_out = "Ranger agent unavailable";
        logRequest(request, "(no response)", false);
        return false;
    }

    // Parse response: "ALLOW" or "DENY\treason"
    bool allowed = false;
    String reason;

    if (response.starts_with("ALLOW"))
    {
        allowed = true;
    }
    else if (response.starts_with("DENY"))
    {
        allowed = false;
        // Extract reason after "DENY\t"
        size_t tab_pos = response.find('\t');
        if (tab_pos != String::npos && tab_pos + 1 < response.size())
        {
            reason = response.substr(tab_pos + 1);
        }
        else
        {
            reason = "denied by Ranger";
        }
    }
    else
    {
        // Malformed response => deny
        allowed = false;
        reason = "malformed response from Ranger: " + response;
        LOG_WARNING(getLogger("RangerClient"), "Malformed response from Ranger agent: {}", response);
    }

    if (reason_out)
        *reason_out = reason;

    logRequest(request, response, allowed);
    return allowed;
}

bool RangerClient::ping()
{
    std::lock_guard lock(mutex);

    String response;
    if (!sendRequestImpl("PING", response))
        return false;

    return response == "PONG";
}

}
