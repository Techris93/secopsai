rule SecOpsAI_Rust_Build_Download_Execute {
  meta:
    rule_id = "OSS-RUST-PROC-MACRO"
    severity = "high"
    confidence = "high"
  strings:
    $build = "build.rs" nocase
    $curl = "Command::new(\"curl\")" nocase
    $wget = "Command::new(\"wget\")" nocase
  condition:
    $build and ($curl or $wget)
}

rule SecOpsAI_PowerShell_Download_Execute {
  meta:
    rule_id = "OSS-POWERSHELL-STAGING"
    severity = "high"
    confidence = "high"
  strings:
    $ps = "powershell" nocase
    $download = "Invoke-WebRequest" nocase
    $execute = "Start-Process" nocase
  condition:
    $ps and ($download or $execute)
}
