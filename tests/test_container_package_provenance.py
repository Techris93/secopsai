import json
import zipfile

from scripts.container_package_provenance import collect
from scripts.summarize_container_security import summarize


def test_collects_filesystem_and_embedded_metadata(tmp_path):
    metadata = tmp_path / "lib" / "setuptools-70.3.0.dist-info" / "METADATA"
    metadata.parent.mkdir(parents=True)
    metadata.write_text("Name: setuptools\nVersion: 70.3.0\n", encoding="utf-8")
    wheel = tmp_path / "usr" / "local" / "lib" / "python" / "ensurepip" / "_bundled" / "msgpack.whl"
    wheel.parent.mkdir(parents=True)
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("msgpack-1.1.2.dist-info/METADATA", "Name: msgpack\nVersion: 1.1.2\n")

    payload = collect(tmp_path, ["msgpack", "setuptools"])

    assert payload["schema_version"] == "secopsai.container-package-provenance.v1"
    assert [(record["normalized_name"], record["version"], record["source_type"]) for record in payload["metadata_records"]] == [
        ("msgpack", "1.1.2", "embedded_archive"),
        ("setuptools", "70.3.0", "filesystem_metadata"),
    ]
    assert payload["matching_archives"][0]["sha256"]


def test_normalizes_trivy_package_path_and_layer():
    report = {
        "ArtifactName": "sha256:abc",
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": "Python",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-TEST",
                        "PkgName": "setuptools",
                        "InstalledVersion": "70.3.0",
                        "FixedVersion": "78.1.1",
                        "Severity": "HIGH",
                        "PkgPath": "/usr/local/lib/python3.10/site-packages/setuptools-70.3.0.dist-info/METADATA",
                        "PkgIdentifier": {"PURL": "pkg:pypi/setuptools@70.3.0"},
                        "Layer": {"Digest": "sha256:layer", "DiffID": "sha256:diff"},
                        "DataSource": {"Name": "GitHub Security Advisory"},
                    }
                ],
            }
        ],
    }

    payload = summarize(report, image_digest="sha256:abc", trivy_version="0.69.3", database_metadata={"UpdatedAt": "now"})

    assert payload["finding_count"] == 1
    finding = payload["findings"][0]
    assert finding["package_path"].endswith("METADATA")
    assert finding["layer_digest"] == "sha256:layer"
    assert finding["package_identifier"] == "pkg:pypi/setuptools@70.3.0"


def test_provenance_payload_is_json_serializable(tmp_path):
    payload = collect(tmp_path, ["msgpack"])
    assert json.loads(json.dumps(payload))["packages"] == ["msgpack"]
