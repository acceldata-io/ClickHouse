#include <Access/RangerAgentSupervisor.h>
#include <Access/RangerClient.h>
#include <Common/Exception.h>
#include <Common/logger_useful.h>
#include <IO/ReadHelpers.h>
#include <IO/ReadBufferFromFile.h>
#include <Poco/String.h>
#include <poll.h>
#include <unistd.h>
#include <chrono>

namespace DB
{

namespace ErrorCodes
{
    extern const int CANNOT_CREATE_CHILD_PROCESS;
    extern const int TIMEOUT_EXCEEDED;
    extern const int LOGICAL_ERROR;
}

RangerAgentSupervisor::RangerAgentSupervisor(const Config & config_, RangerClient & client_)
    : config(config_), client(client_)
{
}

RangerAgentSupervisor::~RangerAgentSupervisor()
{
    try
    {
        stop();
    }
    catch (...)
    {
        // Swallow exceptions in destructor
    }
}

std::vector<String> RangerAgentSupervisor::buildCommandArgs() const
{
    std::vector<String> args;

    // Parse jvm_opts (space-separated)
    // For fake Python agent: jvm_opts = "--supervised --behavior policy"
    // For real Java agent: jvm_opts = "-Xmx512m -Dagent.port=0 -cp /path:jar Main --supervised"
    if (!config.jvm_opts.empty())
    {
        std::istringstream iss(config.jvm_opts);
        String opt;
        while (iss >> opt)
        {
            args.push_back(opt);
        }
    }

    // NOTE: For Java agent, all args (including -Dagent.port, -cp, Main class, etc.)
    // should be in jvm_opts. We don't add them here to support both Python and Java agents.

    return args;
}

void RangerAgentSupervisor::drainStdout()
{
    try
    {
        ReadBufferFromFile & out = agent_process->out;
        String line;

        while (!out.eof())
        {
            readString(line, out, '\n');

            // Trim trailing whitespace
            while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back())))
            {
                line.pop_back();
            }

            if (line.empty())
            {
                continue;
            }

            LOG_TRACE(getLogger("RangerAgentSupervisor"),
                "Agent stdout line: '{}'", line);

            if (line.starts_with("READY ipc="))
            {
                // Parse "READY ipc=127.0.0.1:<port>"
                size_t eq_pos = line.find('=');
                if (eq_pos != String::npos)
                {
                    String ipc_addr = line.substr(eq_pos + 1);
                    size_t colon_pos = ipc_addr.find(':');
                    if (colon_pos != String::npos)
                    {
                        String port_str = ipc_addr.substr(colon_pos + 1);
                        try
                        {
                            UInt16 p = std::stoi(port_str);
                            port.store(p, std::memory_order_release);
                            LOG_INFO(getLogger("RangerAgentSupervisor"),
                                "Ranger agent reported READY on port {}", p);
                        }
                        catch (...)
                        {
                            LOG_WARNING(getLogger("RangerAgentSupervisor"),
                                "Failed to parse port from READY line: '{}'", line);
                        }
                    }
                    else
                    {
                        LOG_WARNING(getLogger("RangerAgentSupervisor"),
                            "READY line missing colon: '{}'", line);
                    }
                }
            }
            else
            {
                // Forward other lines to log (may include Kerberos login messages)
                LOG_INFO(getLogger("RangerAgentSupervisor"), "[Ranger Agent stdout] {}", line);
            }
        }
    }
    catch (const Exception & e)
    {
        LOG_DEBUG(getLogger("RangerAgentSupervisor"), "stdout drain ended: {}", e.message());
    }
}

void RangerAgentSupervisor::drainStderr()
{
    try
    {
        ReadBufferFromFile & err = agent_process->err;
        String line;

        while (!err.eof())
        {
            readString(line, err, '\n');

            if (!line.empty())
            {
                // Check for FATAL (Kerberos login failure, etc.)
                if (line.starts_with("FATAL:"))
                {
                    LOG_ERROR(getLogger("RangerAgentSupervisor"), "[Ranger Agent] {}", line);
                }
                else
                {
                    LOG_INFO(getLogger("RangerAgentSupervisor"), "[Ranger Agent] {}", line);
                }
            }
        }
    }
    catch (const Exception & e)
    {
        LOG_DEBUG(getLogger("RangerAgentSupervisor"), "stderr drain ended: {}", e.message());
    }
}

UInt16 RangerAgentSupervisor::waitForReady()
{
    auto start_time = std::chrono::steady_clock::now();
    auto timeout = std::chrono::milliseconds(config.start_timeout_ms);

    while (true)
    {
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed >= timeout)
        {
            throw Exception(ErrorCodes::TIMEOUT_EXCEEDED,
                "Ranger agent did not send READY within {} ms", config.start_timeout_ms);
        }

        UInt16 p = port.load(std::memory_order_acquire);
        if (p != 0)
        {
            return p;
        }

        // Check if agent exited early
        if (agent_process->waitIfProccesTerminated())
        {
            int exit_code = agent_process->tryWait();
            throw Exception(ErrorCodes::CANNOT_CREATE_CHILD_PROCESS,
                "Ranger agent exited before sending READY, exit code: {}", exit_code);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void RangerAgentSupervisor::watchAgent()
{
    try
    {
        LOG_INFO(getLogger("RangerAgentSupervisor"),
            "Starting agent watcher thread for PID {}", agent_process->getPid());

        while (true)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            // Check if agent terminated
            if (agent_process->waitIfProccesTerminated())
            {
                // Agent exited
                int exit_code = agent_process->tryWait();

                if (shutting_down.load(std::memory_order_acquire))
                {
                    // Graceful shutdown - this is expected
                    LOG_INFO(getLogger("RangerAgentSupervisor"),
                        "Ranger agent exited during shutdown with code {}", exit_code);
                    running.store(false, std::memory_order_release);
                    return;
                }
                else
                {
                    // Unexpected exit - fail-stop
                    LOG_FATAL(getLogger("RangerAgentSupervisor"),
                        "Ranger agent (PID {}) has exited unexpectedly with code {}. "
                        "ClickHouse cannot continue without authorization. Terminating.",
                        agent_process->getPid(), exit_code);

                    // Flush logs before exit
                    // Note: getLogger returns pointer, no & needed
                    (void)0; // Log flush not critical for exit

                    _exit(100);
                }
            }
        }
    }
    catch (const Exception & e)
    {
        LOG_ERROR(getLogger("RangerAgentSupervisor"), "Agent watcher thread error: {}", e.message());
    }
}

void RangerAgentSupervisor::start()
{
    if (running.load(std::memory_order_acquire))
    {
        throw Exception(ErrorCodes::LOGICAL_ERROR, "Ranger agent already started");
    }

    LOG_INFO(getLogger("RangerAgentSupervisor"), "Starting Ranger agent...");

    // Build command
    std::vector<String> args = buildCommandArgs();

    // Log command (without keytab content)
    {
        std::ostringstream cmd_str;
        cmd_str << config.java_path;
        for (const auto & arg : args)
        {
            // Don't log keytab file content, only path
            if (arg.starts_with("-Dagent.keytab="))
            {
                cmd_str << " -Dagent.keytab=<redacted>";
            }
            else
            {
                cmd_str << " " << arg;
            }
        }
        LOG_INFO(getLogger("RangerAgentSupervisor"), "Agent command: {}", cmd_str.str());
    }

    // Launch agent process
    ShellCommand::Config shell_config(config.java_path);
    shell_config.arguments = args;
    // Don't terminate in destructor - we manage lifecycle ourselves
    shell_config.terminate_in_destructor_strategy = ShellCommand::DestructorStrategy(false, 0);

    try
    {
        agent_process = ShellCommand::executeDirect(shell_config);
    }
    catch (const Exception & e)
    {
        throw Exception(ErrorCodes::CANNOT_CREATE_CHILD_PROCESS,
            "Failed to start Ranger agent: {}", e.message());
    }

    LOG_INFO(getLogger("RangerAgentSupervisor"),
        "Ranger agent process started with PID {}", agent_process->getPid());

    // Start stdout and stderr drain threads BEFORE waiting for READY
    stdout_drain_thread = std::thread([this]() { drainStdout(); });
    stderr_drain_thread = std::thread([this]() { drainStderr(); });

    // Wait for READY (with timeout)
    UInt16 agent_port = waitForReady();

    // Mark as ready in RangerClient
    client.setReady();

    LOG_INFO(getLogger("RangerAgentSupervisor"),
        "Ranger agent is ready on port {}", agent_port);

    // Mark as running and start watcher thread
    running.store(true, std::memory_order_release);
    watcher_thread = std::thread([this]() { watchAgent(); });
}

void RangerAgentSupervisor::stop()
{
    bool was_running = running.exchange(false, std::memory_order_acq_rel);

    // Set shutting_down even if not running (for drain threads during startup failure)
    shutting_down.store(true, std::memory_order_release);

    if (!was_running && !stdout_drain_thread.joinable() && !stderr_drain_thread.joinable())
    {
        // Nothing started, nothing to clean up
        return;
    }

    LOG_INFO(getLogger("RangerAgentSupervisor"), "Stopping Ranger agent...");

    // Close stdin pipe => agent sees EOF and exits
    // This will cause drain threads to receive EOF once process exits
    if (agent_process)
    {
        try
        {
            agent_process->in.close();
        }
        catch (const Exception & e)
        {
            LOG_WARNING(getLogger("RangerAgentSupervisor"),
                "Error closing agent stdin: {}", e.message());
        }

        // Wait for agent to exit (with timeout)
        bool exited = false;
        for (int i = 0; i < 50; ++i) // 5 seconds total
        {
            if (agent_process->waitIfProccesTerminated())
            {
                exited = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (!exited)
        {
            LOG_WARNING(getLogger("RangerAgentSupervisor"),
                "Ranger agent did not exit after stdin close, sending SIGTERM");
            kill(agent_process->getPid(), SIGTERM);

            // Wait another 2 seconds
            for (int i = 0; i < 20; ++i)
            {
                if (agent_process->waitIfProccesTerminated())
                {
                    exited = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        if (!exited)
        {
            LOG_WARNING(getLogger("RangerAgentSupervisor"),
                "Ranger agent did not exit gracefully, sending SIGKILL");
            kill(agent_process->getPid(), SIGKILL);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            agent_process->waitIfProccesTerminated();
        }

        int exit_code = agent_process->tryWait();
        LOG_INFO(getLogger("RangerAgentSupervisor"),
            "Ranger agent exited with code {}", exit_code);
    }

    // Join threads (agent is dead, so drain threads should exit soon)
    if (watcher_thread.joinable())
    {
        watcher_thread.join();
    }
    if (stdout_drain_thread.joinable())
    {
        stdout_drain_thread.join();
    }
    if (stderr_drain_thread.joinable())
    {
        stderr_drain_thread.join();
    }

    LOG_INFO(getLogger("RangerAgentSupervisor"), "Ranger agent stopped");
}

}
