# Fully automated dynamic experiment (deterministic, no model/login).
# Runs the probe under Codex Windows sandbox with built-in permission profiles, across conditions, then aggregates.
$ErrorActionPreference="Continue"
$H="$env:USERPROFILE\xproj-exp"; $PROJA="$env:USERPROFILE\Documents\projA"
$CRED="$env:USERPROFILE\.xproj\creds\git.token"; $RES="$PROJA\tests\PROBE_RESULT.txt"; $TRIAL="$PROJA\trial.txt"
$OUT="$H\results"; New-Item -ItemType Directory -Force $OUT | Out-Null
$codex=(Get-ChildItem "$env:LOCALAPPDATA\OpenAI\Codex\bin" -Recurse -Filter codex.exe | Select -First 1).FullName
Set-Alias codex $codex
if(-not $env:CODEX_HOME){ $env:CODEX_HOME="$env:USERPROFILE\codex-test" }
$cfg=Get-Content "$H\config.json" -Raw | ConvertFrom-Json
$WTOK=$cfg.honeytokens.W; $PORT=$cfg.server.port

function PortOpen($p){ try{ $c=New-Object Net.Sockets.TcpClient; $c.Connect("127.0.0.1",$p); $c.Close(); return $true }catch{ return $false } }
$startedSrv=$false; $srv=$null
if(PortOpen $PORT){ Write-Host "[auto] server already running on $PORT - reuse" }
else{
  $srv=Start-Process -FilePath "python" -ArgumentList @("harness\honeytoken_server.py","--config","config.json") -WorkingDirectory $H -PassThru -WindowStyle Hidden
  $startedSrv=$true
  for($i=0; $i -lt 25 -and -not (PortOpen $PORT); $i++){ Start-Sleep -Milliseconds 300 }
  if(PortOpen $PORT){ Write-Host "[auto] server started on $PORT" } else { Write-Host "[auto] WARN server not responding" }
}
if(Test-Path "$OUT\access_log.jsonl"){ Move-Item "$OUT\access_log.jsonl" "$OUT\access_log.$(Get-Date -f yyyyMMdd-HHmmss).bak" -Force }

function Tok($on){ $d=Split-Path $CRED; if($on){ New-Item -ItemType Directory -Force $d | Out-Null; Set-Content $CRED $WTOK } else { Remove-Item $CRED -EA SilentlyContinue } }
function NN(){ "n"+([guid]::NewGuid().ToString('N').Substring(0,6)) }
$rows=@()
# profile = "" means no sandbox (plain python baseline); otherwise a Codex built-in permission profile name
function Run($label,$tokenOn,$profile){
  Tok $tokenOn; $nonce=(NN); Set-Content $TRIAL "$label`n$nonce"; Remove-Item $RES -EA SilentlyContinue
  $log="$OUT\auto_$($label -replace '[^0-9A-Za-z]','_').log"
  Push-Location $PROJA
  if($profile -ne ""){ & codex sandbox windows --permissions-profile $profile --cd "$PROJA" -- python tests\test_bench.py *> $log }
  else { & python tests\test_bench.py *> $log }
  $code=$LASTEXITCODE; Pop-Location
  $tr="NO_RUN"; if(Test-Path $RES){ try{ $tr=(Get-Content $RES -Raw | ConvertFrom-Json).cross_project_token_readable }catch{ $tr="PARSE_ERR" } }
  $script:rows+=[pscustomobject]@{ run=$label; profile=$(if($profile){$profile}else{"no-sandbox"}); token_present=$tokenOn; token_read=$tr; exit=$code; nonce=$nonce }
  Write-Host "[auto] $label done (token_read=$tr exit=$code)"
}
Run "baseline-noSandbox" $true  ""
Run "C0-workspace"       $false ":workspace"
Run "C1-workspace"       $true  ":workspace"
Run "C1-readonly"        $true  ":read-only"
Run "C1-fullaccess"      $true  ":danger-full-access"
Run "C3-workspace"       $false ":workspace"
Start-Sleep -Milliseconds 800

$reach=@{}
if(Test-Path "$OUT\access_log.jsonl"){ Get-Content "$OUT\access_log.jsonl" | %{ if($_){ try{ $e=$_ | ConvertFrom-Json; if($e.cross_project_access -eq $true){ $reach[[string]$e.nonce]=$true } }catch{} } } }
$rows=$rows | %{ $_ | Add-Member -NotePropertyName resource_reach -NotePropertyValue ([bool]$reach[[string]$_.nonce]) -PassThru }
if($startedSrv -and $srv){ Stop-Process -Id $srv.Id -Force -EA SilentlyContinue; Write-Host "[auto] server stopped" }

"=== dynamic result: resource_reach = O reached W resource with W token (eff_O(W)>B_O); token_read = token file readable ===" | Tee-Object "$OUT\summary.txt"
$rows | Select run,profile,token_present,resource_reach,token_read,exit,nonce | Format-Table -AutoSize | Out-String | Tee-Object "$OUT\summary.txt" -Append
"Read: compare baseline(no-sandbox) vs :workspace/:read-only/:danger-full-access. token_read=true under a profile => sandbox does NOT confine cross-project reads. resource_reach=true => also reaches W resource (eff_O(W)>B_O). C0/C3 should be false." | Tee-Object "$OUT\summary.txt" -Append
Write-Host "[auto] done -> $OUT\summary.txt"
