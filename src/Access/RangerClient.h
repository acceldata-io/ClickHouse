#pragma once

#include <memory>
#include <mutex>
#include <atomic>
#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/SocketAddress.h>
#include <base/types.h>

namespace DB
{

/// Client for communicating with the Ranger authorization agent over TCP.
/// Thread-safe, uses a single persistent connection with reconnect on failure.
/// Fail-closed: any error (timeout, disconnect, malformed response) => deny.
class RangerClient
{
public:
    struct Config
    {
        String host = "127.0.0.1";
        UInt16 port = 9099;
        UInt32 connect_timeout_ms = 2000;
        UInt32 send_timeout_ms = 2000;
        UInt32 receive_timeout_ms = 2000;
    };

    explicit RangerClient(const Config & config_);
    ~RangerClient();

    /// Check access for a user. Returns true (allow) or false (deny).
    /// privileges: comma-separated ClickHouse privilege names (e.g., "SELECT,INSERT")
    /// database/table/column: empty string if not specified
    /// reason_out: filled with denial reason from agent if denied (optional)
    /// Thread-safe. Fail-closed: on error, returns false and fills reason_out.
    bool checkAccess(
        const String & user,
        const String & privileges,
        const String & database,
        const String & table,
        const String & column,
        String * reason_out = nullptr);

    /// Ping the agent. Returns true if agent responds with PONG, false otherwise.
    bool ping();

    /// Returns true if the client is ready (READY was received from supervisor).
    /// Before READY, all checkAccess() calls return false (deny).
    bool isReady() const { return ready.load(std::memory_order_acquire); }

    /// Mark as ready (called by RangerAgentSupervisor after READY).
    void setReady() { ready.store(true, std::memory_order_release); }

private:
    Config config;
    mutable std::mutex mutex;
    std::unique_ptr<Poco::Net::StreamSocket> socket;
    std::atomic<bool> ready{false};

    /// Connect to the agent. Must be called with mutex held.
    /// Returns true on success, false on failure.
    bool connectImpl();

    /// Reconnect (close old, connect new). Must be called with mutex held.
    bool reconnectImpl();

    /// Send a request line and receive a response line.
    /// Must be called with mutex held.
    /// Returns true if successful (response in response_out), false on error.
    bool sendRequestImpl(const String & request, String & response_out);

    /// Sanitize a field: reject if contains tab or newline (injection risk).
    /// Throws if invalid.
    static void sanitizeField(const String & field, const String & field_name);

    /// Log at trace/debug level.
    static void logRequest(const String & request, const String & response, bool allowed);
};

}
