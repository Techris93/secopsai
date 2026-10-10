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
    description = "PowerShell that downloads and executes a payload with evasion flags"
  strings:
    $ps = "powershell" nocase
    $dl1 = "Invoke-WebRequest" nocase
    $dl2 = "DownloadString" nocase
    $dl3 = "DownloadFile" nocase
    $dl4 = "Net.WebClient" nocase
    $dl5 = "Invoke-RestMethod" nocase
    $ex1 = "Invoke-Expression" nocase
    $ex2 = /\|\s*iex\b/ nocase
    $ex3 = "Start-Process" nocase
    $ev1 = "-WindowStyle Hidden" nocase
    $ev2 = /-(w|win|windowstyle)\s+h(idden)?\b/ nocase
    $ev3 = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
    $ev4 = /-(ep|executionpolicy)\s+bypass/ nocase
  condition:
    // Install instructions in docs and bundled source maps are not staging.
    not (extension == ".md" or extension == ".markdown" or extension == ".txt" or extension == ".rst" or extension == ".map" or extension == ".html" or extension == ".htm")
    and $ps and any of ($dl*) and any of ($ex*) and any of ($ev*)
}
