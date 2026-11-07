import pytest
from realworld_report import SUMMARIES


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    """Show each scanned repo's findings at the end, with or without -s or -k."""
    if not SUMMARIES:
        return
    terminalreporter.section("secretscan real-world findings")
    for text in SUMMARIES.values():
        terminalreporter.write_line(text)
