# HackPilot core module
"""ToolManager command execution (no shell=True), and session cancellation:
terminate_active_process() exists because /api/session/<id>/cancel used to
only flip the DB status row while the actual tool subprocess (confirmed
live: amass, then whatweb) kept running against the target for minutes
afterward."""

import sys
import threading
import time

import pytest


@pytest.fixture
def tool_manager():
    from advance_hackpilot import ToolManager

    return ToolManager()


def test_run_command_simple_without_shell(tool_manager):
    result = tool_manager.run_command([sys.executable, "-c", "print('ok')"])
    assert result["success"] is True
    assert "ok" in result["stdout"]


def test_run_command_rejects_unsupported_metacharacters(tool_manager):
    result = tool_manager.run_command("echo hi; rm -rf /")
    assert result["success"] is False
    assert "Unsupported" in result["stderr"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shlex pipeline parsing")
def test_run_command_pipe_without_shell(tool_manager):
    cmd = f"{sys.executable} -c \"print('pipe')\" | {sys.executable} -c \"import sys; print(sys.stdin.read().strip())\""
    result = tool_manager.run_command(cmd)
    assert result["success"] is True
    assert "pipe" in result["stdout"]


def test_pipeline_parser_preserves_quoted_pipe(tool_manager):
    result = tool_manager._split_pipeline('grep -E "foo|bar" file.txt')
    assert result == [["grep", "-E", "foo|bar", "file.txt"]]


def test_pipeline_parser_splits_only_unquoted_pipes(tool_manager):
    result = tool_manager._split_pipeline('cat file.txt | grep -E "foo|bar"')
    assert result == [["cat", "file.txt"], ["grep", "-E", "foo|bar"]]


def test_terminate_active_process_kills_a_long_running_command(tool_manager):
    """The real bug: cancelling a session used to only update the DB row,
    leaving whatever tool was mid-run (e.g. amass, with a 900s timeout)
    going for as long as it wanted. run_command must now register the
    subprocess so it can be killed on demand instead of waited out."""
    result_holder = {}

    def run_in_background():
        result_holder["result"] = tool_manager.run_command(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout=60
        )

    thread = threading.Thread(target=run_in_background)
    thread.start()

    # Give the subprocess a moment to actually start before killing it.
    for _ in range(50):
        if tool_manager._active_popen is not None:
            break
        time.sleep(0.1)
    assert tool_manager._active_popen is not None, "subprocess never registered as active"

    started = time.time()
    tool_manager.terminate_active_process()
    thread.join(timeout=10)
    elapsed = time.time() - started

    assert not thread.is_alive()
    assert elapsed < 5, "terminate_active_process() should kill immediately, not wait out the 30s sleep"
    assert result_holder["result"]["success"] is False
    assert tool_manager._active_popen is None


def test_terminate_active_process_is_a_noop_when_nothing_is_running(tool_manager):
    tool_manager.terminate_active_process()  # must not raise
