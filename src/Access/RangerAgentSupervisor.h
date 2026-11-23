#pragma once

#include <memory>
#include <thread>
#include <atomic>
#include <Common/ShellCommand.h>
#include <base/types.h>

namespace DB
{

class RangerClient;

/// Supervisor for the Ranger authorization agent child process.
/// Launches the agent via ShellCommand, waits for READY on stdout,
/// keeps stdin pipe open for the server's lifetime, and watches for agent exit.
/// If the agent exits while ClickHouse is running, calls _exit(100) (fail-stop).
class RangerAgentSupervisor
{
public:
    struct Config
    {
        String java_path;                // Path to java/python executable (required)
        String jar_path;                 // Path to agent JAR or .py script (required)
        String conf_dir;                 // Agent configuration directory (required)
        String jvm_opts;                 // JVM options or script args, space-separated (optional)
        String main_class;               // Java main class (default: com.acceldata.clickhouse.ranger.AgentMain)
        String principal;                // Kerberos principal (optional)
        String keytab_path;              // Kerberos keytab path (optional)
        UInt32 start_timeout_ms = 10000; // Timeout waiting for READY
    };

    explicit RangerAgentSupervisor(const Config & config_, RangerClient & client_);
    ~RangerAgentSupervisor();

    /// Start the agent process and wait for READY on stdout.
    /// Throws on failure (agent didn't start, didn't send READY within timeout, etc.)
    /// This call blocks until READY is received.
    void start();

    /// Stop the agent gracefully (called during shutdown).
    /// Closes stdin pipe and waits for agent to exit.
    /// Sets shutting_down flag so watcher doesn't _exit(100).
    void stop();

    /// Get the agent's port (from "READY ipc=127.0.0.1:<port>").
    UInt16 getPort() const { return port.load(std::memory_order_acquire); }

    /// Check if agent is running.
    bool isRunning() const { return running.load(std::memory_order_acquire); }

private:
    Config config;
    RangerClient & client;

    std::unique_ptr<ShellCommand> agent_process;
    std::atomic<UInt16> port{0};
    std::atomic<bool> running{false};
    std::atomic<bool> shutting_down{false};
    std::atomic<bool> child_reaped{false};  // Track if waitpid already called

    std::thread watcher_thread;
    std::thread stdout_drain_thread;
    std::thread stderr_drain_thread;

    /// Build command line arguments for the agent.
    std::vector<String> buildCommandArgs() const;

    /// Wait for "READY ipc=..." line on stdout, with timeout.
    /// Returns port number on success, throws on timeout or error.
    UInt16 waitForReady();

    /// Drain stdout in a background thread (started before waitForReady).
    /// Looks for "READY ipc=..." line, forwards other lines to log.
    void drainStdout();

    /// Drain stderr in a background thread (started before waitForReady).
    /// Forwards all lines to ClickHouse log with "[Ranger Agent]" prefix.
    void drainStderr();

    /// Watch the agent process in a background thread.
    /// If agent exits while running (and not shutting_down), calls _exit(100).
    void watchAgent();
};

}
