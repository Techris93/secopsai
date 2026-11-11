import json

from secopsai import cli


def test_specialists_runs_lists_without_an_unbound_name(tmp_path, capsys):
    # 2026-11-11: a local re-import in another branch of main() made
    # list_specialist_runs local to the whole function, so this command
    # failed with "referenced before assignment".
    code = cli.main(["specialists", "runs", "--db-path", str(tmp_path / "runs.db")])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["runs"] == []
