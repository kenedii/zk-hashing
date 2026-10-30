# Generates a full Argon2id (m=8 KiB, t=1, p=1) Miden STARK with the native prover,
# logging memory every 15 s. Uses the page file for memory beyond physical RAM.
$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent $PSScriptRoot
$exe   = Join-Path $root 'native-prover\argon2id-zk-prover.exe'
$out   = Join-Path $PSScriptRoot 'argon2id-m8-t1-p1.proof.json'
$mon   = Join-Path $PSScriptRoot 'argon2id-monitor.csv'
$log   = Join-Path $PSScriptRoot 'argon2id-run.log'
$pw='hunter2'; $salt='000102030405060708090a0b0c0d0e0f'
$ch=@('305419896','2596069104','267242409','2271560481')
"start $(Get-Date -Format o)" | Out-File $log
$os = Get-CimInstance Win32_OperatingSystem
"ram_total_gib=$([math]::Round($os.TotalVisibleMemorySize/1MB,1)) commit_limit_gib=$([math]::Round($os.TotalVirtualMemorySize/1MB,1))" | Out-File $log -Append
$cred = & $exe credential $pw $salt 8 1 1
"credential=$cred" | Out-File $log -Append
'time,elapsed_s,private_gib,working_set_gib,peak_working_set_gib,cpu_s,sys_free_ram_gib' | Out-File $mon
$argList = @('prove',$pw,$salt,'8','1','1') + $ch + @('--out',('"'+$out+'"'))
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $exe -PassThru -NoNewWindow `
  -ArgumentList $argList `
  -RedirectStandardOutput (Join-Path $PSScriptRoot 'argon2id-stdout.txt') `
  -RedirectStandardError  (Join-Path $PSScriptRoot 'argon2id-stderr.txt')
try { $p.PriorityClass = 'BelowNormal' } catch {}
$peakPriv = 0
while (-not $p.HasExited) {
  Start-Sleep -Seconds 15
  try {
    $p.Refresh()
    $priv = $p.PrivateMemorySize64/1GB; if ($priv -gt $peakPriv) { $peakPriv = $priv }
    $free = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1MB
    '{0},{1:N0},{2:N2},{3:N2},{4:N2},{5:N0},{6:N1}' -f (Get-Date -Format s),$sw.Elapsed.TotalSeconds,$priv,($p.WorkingSet64/1GB),($p.PeakWorkingSet64/1GB),$p.TotalProcessorTime.TotalSeconds,$free | Out-File $mon -Append
  } catch {}
}
$p.WaitForExit()
"exit_code=$($p.ExitCode) elapsed_s=$([math]::Round($sw.Elapsed.TotalSeconds)) peak_private_gib=$([math]::Round($peakPriv,2))" | Out-File $log -Append
if ($p.ExitCode -eq 0) {
  $expText = '{"credential":[' + $cred.Trim('[',']') + '],"challenge":[' + ($ch -join ',') + '],"saltHex":"' + $salt + '","params":{"algorithm":"argon2id","parameters":{"memoryKiB":8,"timeCost":1,"lanes":1}}}'
  $expPath = Join-Path $PSScriptRoot 'argon2id-expected.json'
  [IO.File]::WriteAllText($expPath, $expText)
  $v = & $exe verify-file $out $expPath 2>&1
  "verify=$v" | Out-File $log -Append
  "proof_bytes=$((Get-Item $out).Length)" | Out-File $log -Append
}
"end $(Get-Date -Format o)" | Out-File $log -Append
