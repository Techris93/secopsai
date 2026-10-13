import hashlib
import json
import os
import zipfile

import pytest

import soc_store
from secopsai.research_artifacts import import_artifact
from secopsai.research_artifact_vault import backup_artifact, restore_artifact, VaultClient
from secopsai.research_assurance import register_person
from secopsai.research_operation_store import records


class MemoryVault:
    def __init__(self):
        self.objects = {}

    def put(self, body):
        key = hashlib.sha256(body).hexdigest()
        self.objects[key] = body
        return key

    def get(self, key):
        return self.objects[key]


@pytest.fixture
def artifact(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    db = str(tmp_path / "ledger.db")
    register_person({"person_id": "operator.owner", "display_name": "Fixture", "roles": ["operator"], "qualification": "Synthetic fixture"}, actor="operator.owner", db_path=db)
    path = tmp_path / "package.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("package.json", '{"name":"fixture","version":"1"}')
    result = import_artifact(str(path), provenance={"source": "synthetic authorized sample"}, db_path=db)
    with soc_store.connect(db) as conn:
        stored = conn.execute("SELECT quarantine_path FROM research_artifacts WHERE artifact_id=?", (result["artifact_id"],)).fetchone()[0]
    return db, result["artifact_id"], stored, path.read_bytes()


def test_backup_restore_bytes_and_idempotent_receipt(artifact):
    db, identity, stored, original = artifact
    client = MemoryVault()
    options = dict(actor="operator.owner", db_path=db, client=client, cloud_storage_authorized=True)
    saved = backup_artifact(identity, **options)
    assert saved == backup_artifact(identity, **options)
    assert len(records("artifact_backup", db_path=db)) == 1
    os.unlink(stored)
    restored = restore_artifact(identity, actor="operator.owner", db_path=db, client=client)
    assert restored["hash_verified"] and not restored["execution_performed"]
    with soc_store.connect(db) as conn:
        path = conn.execute("SELECT quarantine_path FROM research_artifacts WHERE artifact_id=?", (identity,)).fetchone()[0]
    assert open(path, "rb").read() == original
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_corrupt_recovery_does_not_replace_existing_artifact(artifact):
    db, identity, stored, original = artifact
    client = MemoryVault()
    saved = backup_artifact(identity, actor="operator.owner", db_path=db, client=client, cloud_storage_authorized=True)
    manifest = json.loads(client.objects[saved["manifest_sha256"]])
    client.objects[manifest["chunks"][0]["sha256"]] = b"corrupt"
    with pytest.raises(ValueError, match="integrity"):
        restore_artifact(identity, actor="operator.owner", db_path=db, client=client)
    assert open(stored, "rb").read() == original
    assert not records("artifact_restore", db_path=db)


def test_private_authorization_symlink_and_partial_backup(artifact):
    db, identity, stored, _ = artifact
    client = MemoryVault()
    with pytest.raises(ValueError, match="authorization"):
        backup_artifact(identity, actor="operator.owner", db_path=db, client=client)
    destination = stored + ".original"
    os.rename(stored, destination)
    os.symlink(destination, stored)
    with pytest.raises(OSError):
        backup_artifact(identity, actor="operator.owner", db_path=db, client=client, cloud_storage_authorized=True)
    assert not records("artifact_backup", db_path=db)


def test_invalid_origin_and_credentials_do_not_make_network_calls():
    for url in ["http://example.com", "https://token@example.com", "https://example.com/path", "https://example.com?x=1"]:
        with pytest.raises(ValueError):
            VaultClient(url=url, token="synthetic")
