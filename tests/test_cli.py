from __future__ import annotations

from click.testing import CliRunner

from aisafeguard.cli.main import cli


def test_cli_init_and_validate() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        init_result = runner.invoke(cli, ["init"])
        assert init_result.exit_code == 0
        validate_result = runner.invoke(cli, ["validate", "aisafe.yaml"])
        assert validate_result.exit_code == 0
        assert "Config is valid!" in validate_result.output
