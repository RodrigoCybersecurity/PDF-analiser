param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile
)

$ErrorActionPreference = "Stop"

if (!(Test-Path $InputFile)) {
    Write-Host "Ficheiro não encontrado: $InputFile"
    exit 1
}

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Reports = Join-Path $Root "reports"
$Accepted = Join-Path $Root "accepted"
$Rejected = Join-Path $Root "rejected"

New-Item -ItemType Directory -Force -Path $Reports, $Accepted, $Rejected | Out-Null

$Base = Split-Path $InputFile -Leaf
$Name = [System.IO.Path]::GetFileNameWithoutExtension($Base)

$PdfidReport = Join-Path $Reports "${Name}_pdfid.txt"
$VerdictJson = Join-Path $Reports "${Name}_verdict.json"

Write-Host "[1/4] Análise com pdfid.py"
python "$Root\triage\pdfid.py" "$InputFile" | Tee-Object -FilePath $PdfidReport

$Content = Get-Content $PdfidReport -Raw
$Suspicious = $false

if ($Content -match '/JavaScript\s+[1-9]') { $Suspicious = $true }
if ($Content -match '/OpenAction\s+[1-9]') { $Suspicious = $true }
if ($Content -match '/AA\s+[1-9]') { $Suspicious = $true }
if ($Content -match '/Launch\s+[1-9]') { $Suspicious = $true }
if ($Content -match '/EmbeddedFile\s+[1-9]') { $Suspicious = $true }
if ($Content -match '/URI\s+[1-9]') { $Suspicious = $true }

if (-not $Suspicious) {
    Write-Host "[2/4] Sem indicadores críticos. Aceite por análise estática."
    Copy-Item $InputFile (Join-Path $Accepted $Base) -Force

    @"
{
  "file": "$Base",
  "status": "accepted",
  "source": "static",
  "reason": "pdfid sem indicadores críticos"
}
"@ | Set-Content -Encoding UTF8 $VerdictJson

    Write-Host "[3/4] Copiado para accepted\"
    Write-Host "[4/4] Verdict:"
    Get-Content $VerdictJson
    exit 0
}

Write-Host "[2/4] Indicadores suspeitos encontrados. A enviar para sandbox."

$FullInput = (Resolve-Path $InputFile).Path
$FullReports = (Resolve-Path $Reports).Path

docker compose run --rm `
  -v "${FullInput}:/input.pdf:ro" `
  sandbox /input.pdf /output/"$(Split-Path $VerdictJson -Leaf)"

$Verdict = Get-Content $VerdictJson -Raw | ConvertFrom-Json

if ($Verdict.status -eq "accepted") {
    Copy-Item $InputFile (Join-Path $Accepted $Base) -Force
    Write-Host "[3/4] Sandbox aceitou. Copiado para accepted\"
} else {
    Copy-Item $InputFile (Join-Path $Rejected $Base) -Force
    Write-Host "[3/4] Sandbox rejeitou. Copiado para rejected\"
}

Write-Host "[4/4] Verdict:"
Get-Content $VerdictJson