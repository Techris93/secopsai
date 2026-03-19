"""
SPDX-FileCopyrightText: 2026 Techris93
SPDX-License-Identifier: MIT

Installer metadata for secopsai (editable install for development).
"""

from setuptools import setup, find_packages


setup(
    name="secopsai",
    version="0.0.0",
    description="SecOps AI toolkit",
    packages=find_packages(exclude=("tests", "docs")),
    py_modules=[
        "confidence",
        "detect",
        "evaluate",
        "evaluate_openclaw",
        "explain",
        "export_real_openclaw_native",
        "feedback",
        "findings",
        "generate_openclaw_attack_mix",
        "ingest_openclaw",
        "openclaw_findings",
        "openclaw_plugin",
        "openclaw_prepare",
        "prepare",
        "run_openclaw_live",
        "shadow",
        "soc_store",
        "swarm",
        "tune",
        "twilio_whatsapp_webhook",
        "whatsapp_openclaw_router",
    ],
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "secopsai=secopsai.cli:main",
        ],
    },
)
