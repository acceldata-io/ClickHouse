#!/usr/bin/env python3
"""
Fake Ranger agent for testing ClickHouse Ranger integration.
Implements the agent wire protocol: CHECK, PING, --supervised mode.
"""

import sys
import socket
import threading
import argparse
import time
import select

class FakeRangerAgent:
    def __init__(self, port=0, supervised=False, behavior='allow-all'):
        """
        behavior options:
          - 'allow-all': Allow everything
          - 'deny-all': Deny everything
          - 'policy': Apply simple test policy (admin: select/show, clickhouse: all except drop on 'secret')
          - 'slow': Delay 3 seconds before responding (test timeout)
          - 'garbage': Send garbage response (test malformed)
        """
        self.port = port
        self.supervised = supervised
        self.behavior = behavior
        self.server_socket = None
        self.running = True

    def apply_policy(self, user, privileges, database, table, column):
        """Simple test policy matching the brief's fixture policies."""
        privs = [p.strip().upper().replace('_', ' ') for p in privileges.split(',')]

        if user == 'admin':
            # admin: select, show on all
            allowed_privs = {'SELECT', 'SHOW', 'SHOW DATABASES', 'SHOW TABLES', 'SHOW COLUMNS', 'SHOW DICTIONARIES'}
            for priv in privs:
                if priv not in allowed_privs:
                    return False, f"admin can only SELECT/SHOW"
            return True, ""

        elif user == 'clickhouse':
            # clickhouse: all on all, except drop on table 'secret' and select on column 'sc' of table 'secret'
            for priv in privs:
                if priv.startswith('DROP') and table == 'secret':
                    return False, f"DROP denied on table secret"
                if priv == 'SELECT' and table == 'secret' and column == 'sc':
                    return False, f"SELECT denied on column sc of table secret"
            return True, ""

        else:
            # No policy => deny
            return False, f"no policy for user {user}"

    def handle_request(self, line):
        """Process one request line and return response line."""
        parts = line.strip().split('\t')

        if not parts:
            return "DENY\tmalformed request\n"

        command = parts[0]

        if command == 'PING':
            return "PONG\n"

        elif command == 'CHECK':
            if len(parts) < 6:
                return "DENY\tmissing fields\n"

            user = parts[1]
            privileges = parts[2]
            database = parts[3]
            table = parts[4]
            column = parts[5] if len(parts) > 5 else ""

            # MVP: require database
            if not database:
                return "DENY\tdatabase required (MVP)\n"

            # Apply behavior
            if self.behavior == 'allow-all':
                return "ALLOW\n"
            elif self.behavior == 'deny-all':
                return "DENY\tdenied by fake agent (deny-all mode)\n"
            elif self.behavior == 'slow':
                time.sleep(3)
                return "ALLOW\n"
            elif self.behavior == 'garbage':
                return "GARBAGE_RESPONSE_1234567890\n"
            elif self.behavior == 'policy':
                allowed, reason = self.apply_policy(user, privileges, database, table, column)
                if allowed:
                    return "ALLOW\n"
                else:
                    return f"DENY\t{reason}\n"
            else:
                return "DENY\tunknown behavior\n"

        else:
            return "DENY\tunknown command\n"

    def handle_client(self, conn, addr):
        """Handle one client connection."""
        try:
            while self.running:
                # Set timeout for recv
                conn.settimeout(60.0)
                data = conn.recv(65536)
                if not data:
                    break

                lines = data.decode('utf-8').split('\n')
                for line in lines:
                    if line.strip():
                        response = self.handle_request(line)
                        conn.sendall(response.encode('utf-8'))
        except Exception as e:
            print(f"[Agent] Client handler error: {e}", file=sys.stderr)
        finally:
            conn.close()

    def run(self):
        """Start the agent server."""
        # Create listening socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('127.0.0.1', self.port))
        self.server_socket.listen(5)

        actual_port = self.server_socket.getsockname()[1]

        # Print READY message on stdout (ClickHouse waits for this)
        print(f"READY ipc=127.0.0.1:{actual_port}", flush=True)

        # In supervised mode, start stdin watcher
        if self.supervised:
            stdin_thread = threading.Thread(target=self.watch_stdin, daemon=True)
            stdin_thread.start()

        print(f"[Agent] Listening on 127.0.0.1:{actual_port}, behavior={self.behavior}", file=sys.stderr)

        # Accept connections
        try:
            while self.running:
                # Use select with timeout to allow clean shutdown
                readable, _, _ = select.select([self.server_socket], [], [], 1.0)
                if readable:
                    conn, addr = self.server_socket.accept()
                    # Handle in a thread
                    client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                    client_thread.start()
        except KeyboardInterrupt:
            print("[Agent] Interrupted", file=sys.stderr)
        finally:
            self.server_socket.close()
            print("[Agent] Shut down", file=sys.stderr)

    def watch_stdin(self):
        """Watch stdin and exit when it closes (supervised mode)."""
        try:
            while True:
                data = sys.stdin.read(1)
                if not data:
                    # EOF on stdin => exit
                    print("[Agent] stdin closed, exiting (supervised mode)", file=sys.stderr)
                    self.running = False
                    sys.exit(0)
        except Exception as e:
            print(f"[Agent] stdin watcher error: {e}", file=sys.stderr)
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Fake Ranger agent for ClickHouse testing')
    parser.add_argument('--supervised', action='store_true', help='Supervised mode: exit when stdin closes')
    parser.add_argument('--port', type=int, default=0, help='Port to listen on (0 = auto)')
    parser.add_argument('--behavior', choices=['allow-all', 'deny-all', 'policy', 'slow', 'garbage'],
                        default='policy', help='Agent behavior')

    args = parser.parse_args()

    agent = FakeRangerAgent(port=args.port, supervised=args.supervised, behavior=args.behavior)
    agent.run()

if __name__ == '__main__':
    main()
