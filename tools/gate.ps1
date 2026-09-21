$stale = Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
  Where-Object { $_.CommandLine -match 'dns_server|dot_server|phase5' }
$ports = @()
$ports += Get-NetUDPEndpoint -LocalPort 5053 -ErrorAction SilentlyContinue
$ports += Get-NetTCPConnection -LocalPort 5000,853 -State Listen -ErrorAction SilentlyContinue
if ($stale -or $ports) {
  "GATE DIRTY"
  $stale | Select-Object ProcessId, CommandLine | Format-List
  $ports | Select-Object LocalPort, OwningProcess | Format-Table
  exit 1
}
"GATE CLEAN"