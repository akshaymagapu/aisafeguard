from __future__ import annotations

from click.testing import CliRunner

from aisafeguard.cli.main import cli


def test_redteam_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["redteam"])
    assert result.exit_code == 0
    assert "Redteam" in result.output
