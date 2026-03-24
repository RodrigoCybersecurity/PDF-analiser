param(
    [Parameter(Mandatory=$false, ValueFromRemainingArguments=$true)]
    [string[]]$Targets
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Push-Location $Root
try {
    if (-not $Targets -or $Targets.Count -eq 0) {
        python -m file_analyser --incoming
    }
    else {
        python -m file_analyser @Targets
    }
}
finally {
    Pop-Location
}
