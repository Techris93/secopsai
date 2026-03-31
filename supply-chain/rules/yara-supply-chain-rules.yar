# YARA Rules for Supply Chain Attack Detection
# Place in: /etc/yara/rules/ or your EDR's YARA directory
# Usage: yara -r supply-chain-rules.yar /path/to/scan

rule AxioSupplyChainRAT {
    meta:
        description = "Detects Axios supply chain RAT dropper (March 2026)"
        author = "SecOpsAI"
        reference = "https://www.picussecurity.com/resource/blog/axios-npm-supply-chain-attack"
        date = "2026-03-31"
        hash = "known_malicious_hash_placeholder"
        
    strings:
        // Postinstall hook indicator
        $postinstall = "postinstall" ascii wide
        $setup_js = "setup.js" ascii wide
        
        // C2 infrastructure
        $c2_domain = "sfrclak" ascii wide
        $c2_port = ":8000" ascii wide
        
        // Beacon endpoints
        $product0 = "/product0" ascii wide  // macOS
        $product1 = "/product1" ascii wide  // Windows
        $product2 = "/product2" ascii wide  // Linux
        
        // Payload paths
        $apple_disguise = "com.apple.act.mond" ascii wide
        $wt_disguise = "wt.exe" ascii wide
        $ld_py = "ld.py" ascii wide
        
        // Execution patterns
        $nohup = "nohup" ascii wide
        $exec_sync = "execSync" ascii wide
        $apple_script = "osascript" ascii wide
        
    condition:
        filesize < 500KB and
        (
            ($postinstall and $setup_js) or
            $c2_domain or
            (any of ($product*)) or
            (any of ($apple_disguise, $wt_disguise, $ld_py))
        )
}

rule LiteLLM_SupplyChain_Backdoor {
    meta:
        description = "Detects LiteLLM supply chain backdoor (March 2026)"
        author = "SecOpsAI"
        reference = "https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html"
        date = "2026-03-24"
        
    strings:
        // Malicious versions
        $version_1 = "1.82.7" ascii wide
        $version_2 = "1.82.8" ascii wide
        
        // .pth file execution
        $pth_file = "litellm_init.pth" ascii wide
        
        // C2 domains
        $c2_models = "models.litellm.cloud" ascii wide
        $c2_checkmarx = "checkmarx.zone" ascii wide
        
        // Persistence files
        $sysmon_py = "sysmon.py" ascii wide
        $sysmon_service = "sysmon.service" ascii wide
        $telemetry = "System Telemetry Service" ascii wide
        
        // Encryption indicators
        $rsa_4096 = "RSA-4096" ascii wide
        $aes_256 = "AES-256" ascii wide
        $tpcp_tar = "tpcp.tar.gz" ascii wide
        
        // Layered payload structure
        $base64_script = "B64_SCRIPT" ascii wide
        $persist_b64 = "PERSIST_B64" ascii wide
        
    condition:
        filesize < 5MB and
        (
            (any of ($version_*)) or
            $pth_file or
            (any of ($c2_*)) or
            (any of ($sysmon_*)) or
            $telemetry or
            ($rsa_4096 and $aes_256) or
            $tpcp_tar or
            ($base64_script and $persist_b64)
        )
}

rule ShaiHulud_Worm_Payload {
    meta:
        description = "Detects Shai-Hulud 2.0 worm payloads"
        author = "SecOpsAI"
        reference = "https://www.kaspersky.com/blog/supply-chain-attacks-in-2025/55522/"
        date = "2025-11-24"
        
    strings:
        // Repository creation patterns
        $repo_pattern1 = "s1ngularity-repository" ascii wide
        $repo_pattern2 = "Shai Hulud" ascii wide
        $repo_pattern3 = "The Second Coming" ascii wide
        
        // Stolen credential files
        $cloud_json = "cloud.json" ascii wide
        $truffle_secrets = "truffleSecrets.json" ascii wide
        
        // GitHub Actions abuse
        $formatter_workflow = "formatter.yaml" ascii wide
        $discussion_yaml = "discussion.yaml" ascii wide
        $toJSON_secrets = "toJSON(secrets)" ascii wide
        
        // Runner registration
        $sha1hulud_runner = "SHA1HULUD" ascii wide
        
        // Fingerprinting
        $ci_detection = "CI" ascii wide
        $github_actions = "GITHUB_ACTIONS" ascii wide
        
    condition:
        filesize < 1MB and
        (
            (any of ($repo_pattern*)) or
            $cloud_json or
            $truffle_secrets or
            $formatter_workflow or
            $discussion_yaml or
            $sha1hulud_runner or
            ($ci_detection and $github_actions and $toJSON_secrets)
        )
}

rule Vim_TarPlugin_Exploit {
    meta:
        description = "Detects malicious TAR archives exploiting Vim tar.vim (CVE-2025-27423)"
        author = "SecOpsAI"
        reference = "CVE-2025-27423"
        date = "2025-03-03"
        
    strings:
        // TAR header magic
        $tar_magic = { 75 73 74 61 72 }  // "ustar"
        
        // Malicious filename patterns in TAR
        $cmd_chain1 = ".txt;" ascii
        $cmd_chain2 = ".md|" ascii
        $cmd_chain3 = ".js&&" ascii
        $cmd_chain4 = ".py`" ascii
        
        // Shell execution in filenames
        $shell_exec1 = "curl" ascii nocase
        $shell_exec2 = "wget" ascii nocase
        $shell_exec3 = "bash" ascii nocase
        $shell_exec4 = "sh -c" ascii nocase
        
    condition:
        $tar_magic and
        (
            (any of ($cmd_chain*)) or
            (
                filesize < 10MB and
                (
                    ($shell_exec1 and "http" in (filesize-500..filesize)) or
                    ($shell_exec2 and "http" in (filesize-500..filesize)) or
                    ($shell_exec3 and any of ($cmd_chain*)) or
                    ($shell_exec4 and any of ($cmd_chain*))
                )
            )
        )
}

rule Emacs_URI_CommandInjection {
    meta:
        description = "Detects malicious content exploiting Emacs URI handlers (CVE-2025-1244)"
        author = "SecOpsAI"
        reference = "CVE-2025-1244"
        date = "2025-02-12"
        
    strings:
        // Malicious man: URIs
        $man_uri1 = "man:/bin/" ascii wide
        $man_uri2 = "man:/usr/bin/" ascii wide
        $man_uri3 = "man:/sbin/" ascii wide
        $man_uri4 = "man:`" ascii wide
        $man_uri5 = "man:$" ascii wide
        
        // Emacs click handlers
        $emacs_click = "browse-url" ascii wide
        $emacs_man = "man.el" ascii wide
        
        // Command injection patterns in man pages
        $cmd_inject1 = "man:" ascii wide nocase + ";" ascii wide
        $cmd_inject2 = "man:" ascii wide nocase + "|" ascii wide
        $cmd_inject3 = "man:" ascii wide nocase + "&&" ascii wide
        
    condition:
        filesize < 5MB and
        (
            (any of ($man_uri*)) or
            ($emacs_click and $emacs_man and (any of ($cmd_inject*)))
        )
}

rule NPM_Postinstall_Dropper {
    meta:
        description = "Generic detection for npm postinstall dropper scripts"
        author = "SecOpsAI"
        reference = "Generic supply chain detection"
        
    strings:
        // Postinstall entry point
        $postinstall = "postinstall" ascii wide
        
        // Common dropper behaviors
        $platform_check1 = "process.platform" ascii wide
        $platform_check2 = "os.platform()" ascii wide
        $platform_check3 = "navigator.platform" ascii wide
        
        // Download patterns
        $download1 = "http.get" ascii wide
        $download2 = "https.get" ascii wide
        $download3 = "request(" ascii wide
        $download4 = "fetch(" ascii wide
        $download5 = "curl " ascii wide nocase
        $download6 = "wget " ascii wide nocase
        
        // Execution patterns
        $exec1 = "exec(" ascii wide
        $exec2 = "execSync" ascii wide
        $exec3 = "spawn(" ascii wide
        $exec4 = "child_process" ascii wide
        
        // Obfuscation indicators
        $obf1 = "eval(" ascii wide
        $obf2 = "Function(" ascii wide
        $obf3 = "atob(" ascii wide
        $obf4 = "Buffer.from" ascii wide + "base64" ascii wide
        
        // Self-deletion
        $self_delete1 = "fs.unlink" ascii wide
        $self_delete2 = "fs.rm" ascii wide
        $self_delete3 = "fs.rmdir" ascii wide
        
    condition:
        filesize < 1MB and
        $postinstall and
        (
            (any of ($platform_check*)) or
            (any of ($download*) and any of ($exec*)) or
            (any of ($obf*) and any of ($exec*)) or
            (any of ($self_delete*) and any of ($download*))
        )
}

rule Python_PTH_Execution {
    meta:
        description = "Detects malicious Python .pth files (T1546.018)"
        author = "SecOpsAI"
        reference = "MITRE ATT&CK T1546.018"
        
    strings:
        // .pth file in site-packages
        $site_packages = "/site-packages/" ascii wide
        
        // Python execution in .pth
        $python_exec1 = "import" ascii wide
        $python_exec2 = "exec(" ascii wide
        $python_exec3 = "eval(" ascii wide
        $python_exec4 = "__import__" ascii wide
        $python_exec5 = "os.system" ascii wide
        $python_exec6 = "subprocess" ascii wide
        
        // Obfuscation
        $obf1 = "base64" ascii wide + "decode" ascii wide
        $obf2 = "decode(" ascii wide
        $obf3 = "encode(" ascii wide
        
    condition:
        filesize < 100KB and
        $site_packages and
        (any of ($python_exec*)) and
        (any of ($obf*))
}

rule SupplyChain_Typosquat_Package {
    meta:
        description = "Detects potential typosquatting in package names"
        author = "SecOpsAI"
        
    strings:
        // Common typosquats of popular packages
        $axios_typos1 = "sync-axios" ascii wide
        $axios_typos2 = "axios-http-client" ascii wide
        $axios_typos3 = "node-axios" ascii wide
        $axios_typos4 = "axios-wrapper" ascii wide
        
        $lodash_typos1 = "loadsh" ascii wide
        $lodash_typos2 = "lodahs" ascii wide
        $lodash_typos3 = "lodash-es" ascii wide fullword
        
        $express_typos1 = "expres" ascii wide
        $express_typos2 = "express-js" ascii wide
        $express_typos3 = "node-express" ascii wide
        
        $react_typos1 = "reac" ascii wide
        $react_typos2 = "react-js" ascii wide
        $react_typos3 = "node-react" ascii wide
        
    condition:
        filesize < 10KB and
        (
            (any of ($axios_typos*)) or
            (any of ($lodash_typos*)) or
            (any of ($express_typos*)) or
            (any of ($react_typos*))
        )
}
