param([int]$Port = 4173)

$ErrorActionPreference = 'Stop'
$WebRoot = (Resolve-Path $PSScriptRoot).Path
python (Join-Path $WebRoot 'server.py') --port $Port --directory $WebRoot
