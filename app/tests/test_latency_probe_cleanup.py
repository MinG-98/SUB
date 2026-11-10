import subprocess

from app.latency import _stop_hysteria_process


def test_hysteria_stdout_reader_is_joined_before_pipe_close():
    events = []

    class Stdout:
        def close(self):
            assert "reader_joined" in events
            events.append("stdout_closed")

    class Process:
        stdout = Stdout()

        def terminate(self):
            events.append("terminated")

        def wait(self, timeout):
            events.append("waited")
            return 0

    class Reader:
        def join(self):
            assert "waited" in events
            events.append("reader_joined")

    _stop_hysteria_process(Process(), Reader())

    assert events == ["terminated", "waited", "reader_joined", "stdout_closed"]


def test_hysteria_cleanup_kills_a_client_that_does_not_stop():
    events = []

    class Process:
        stdout = None

        def terminate(self):
            events.append("terminated")

        def wait(self, timeout):
            events.append("waited")
            if events.count("waited") == 1:
                raise subprocess.TimeoutExpired("hysteria", timeout)
            return 0

        def kill(self):
            events.append("killed")

    _stop_hysteria_process(Process(), None)

    assert events == ["terminated", "waited", "killed", "waited"]
