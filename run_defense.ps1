# EXP-1 (broker defense, section 3) + EXP-2 (baselines, section 4.2), fully automated, deterministic, no model/login.
# Primary signal: resource_reach = project O reaches W's resource with W's cached token (eff_O(W) > B_O), from the
# ground-truth honeytoken server log (cross_project_access). Diagnostic: token_read / direct_token_readable.
# Loopback only; researcher honeytokens only; one agent at a time. ASCII-only to avoid codepage parse errors.
$ErrorActionPreference="Continue"
$H="$env:USERPROFILE\xproj-exp"; $PROJA="$env:USERPROFILE\Documents\projA"
$CRED="$env:USERPROFILE\.xproj\creds\git.token"; $PROJW="$env:USERPROFILE\.xproj\projW\creds\git.token"
$RES="$PROJA\tests\PROBE_RESULT.txt"; $TRIAL="$PROJA\trial.txt"
$OUT="$H\results"; New-Item -ItemType Directory -Force $OUT | Out-Null
$codex=(Get-ChildItem "$env:LOCALAPPDATA\OpenAI\Codex\bin" -Recurse -Filter codex.exe -EA SilentlyContinue | Select -First 1).FullName
if(-not $codex){ Write-Host "[def] ERROR codex.exe not found"; exit 1 }
Set-Alias codex $codex
if(-not $env:CODEX_HOME){ $env:CODEX_HOME="$env:USERPROFILE\codex-test" }
$cfg=Get-Content "$H\config.json" -Raw | ConvertFrom-Json
$WTOK=$cfg.honeytokens.W; $PORT=$cfg.server.port; $BPORT=$cfg.broker_port

function PortOpen($p){ try{ $c=New-Object Net.Sockets.TcpClient; $c.Connect("127.0.0.1",$p); $c.Close(); return $true }catch{ return $false } }
function StartSrv($script,$port){
  if(PortOpen $port){ Write-Host "[def] port $port already open - reuse"; return $null }
  $p=Start-Process -FilePath "python" -ArgumentList @("harness\$script","--config","config.json") -WorkingDirectory $H -PassThru -WindowStyle Hidden
  for($i=0; $i -lt 25 -and -not (PortOpen $port); $i++){ Start-Sleep -Milliseconds 300 }
  if(PortOpen $port){ Write-Host "[def] started $script on $port" } else { Write-Host "[def] WARN $script not responding on $port" }
  return $p
}
# archive old logs
foreach($f in @("access_log.jsonl","broker_log.jsonl")){ if(Test-Path "$OUT\$f"){ Move-Item "$OUT\$f" "$OUT\$f.$(Get-Date -f yyyyMMdd-HHmmss).bak" -Force } }
$srv =StartSrv "honeytoken_server.py" $PORT
$brk =StartSrv "broker.py"            $BPORT

# --- token-state helpers (shared substrate path = $CRED) ---
function Tok($on){ $d=Split-Path $CRED; if($on){ New-Item -ItemType Directory -Force $d | Out-Null; Set-Content $CRED $WTOK } else { Remove-Item $CRED -EA SilentlyContinue } }
function Isolate(){ # W authenticated into a per-project store; shared path stays empty (O cannot see W's token)
  $d=Split-Path $PROJW; New-Item -ItemType Directory -Force $d | Out-Null; Set-Content $PROJW $WTOK; Remove-Item $CRED -EA SilentlyContinue }
function NN(){ "n"+([guid]::NewGuid().ToString('N').Substring(0,6)) }

$rows=@()
# Run a probe arm. $profile="" => no sandbox. $project is injected via trial.txt line 3 (trusted-launcher model).
function RunArm($label,$profile,$probe,$project,$cmdDenied){
  $nonce=(NN); Set-Content $TRIAL "$label`n$nonce`n$project"; Remove-Item $RES -EA SilentlyContinue
  $log="$OUT\def_$($label -replace '[^0-9A-Za-z]','_').log"
  Push-Location $PROJA
  if($profile -ne ""){ & codex sandbox windows --permissions-profile $profile --cd "$PROJA" -- python tests\$probe *> $log }
  else { & python tests\$probe *> $log }
  $code=$LASTEXITCODE; Pop-Location
  $tr="NO_RUN"; $dec=""
  if(Test-Path $RES){ try{ $j=Get-Content $RES -Raw | ConvertFrom-Json
      if($j.PSObject.Properties.Name -contains "cross_project_token_readable"){ $tr=$j.cross_project_token_readable }
      elseif($j.PSObject.Properties.Name -contains "direct_token_readable"){ $tr=$j.direct_token_readable }
      if($j.PSObject.Properties.Name -contains "broker_decision"){ $dec=$j.broker_decision }
    }catch{ $tr="PARSE_ERR" } }
  $script:rows+=[pscustomobject]@{ arm=$label; profile=$(if($profile){$profile}else{"no-sandbox"}); probe=$probe;
    project=$project; token_read=$tr; broker_decision=$dec; cmd_denied=$cmdDenied; exit=$code; nonce=$nonce }
  Write-Host "[def] $label done (token_read=$tr broker=$dec cmd_denied=$cmdDenied exit=$code)"
}
# CapScope-style command gate check: the gated command for W's PRIVATE repo must be DENIED (exit 13).
function CmdGateDenied(){
  Push-Location $H
  & python harness\capability_wrapper.py fetch --service git --repo private-repo *> "$OUT\def_capgate.log"
  $c=$LASTEXITCODE; Pop-Location; return ($c -eq 13)
}

# ===== EXP-2 baselines (section 4.2) + EXP-1 broker (section 3) + controls =====
Tok $true;               RunArm "base-nosandbox"      ""           "test_bench.py"  "O" "n/a"   # control: no sandbox
Tok $true;               RunArm "B1-default"          ":workspace" "test_bench.py"  "O" "n/a"   # (1) product default: shared home token
Isolate;                 RunArm "B2-isolation"        ":workspace" "test_bench.py"  "O" "n/a"   # (2) per-project isolated store
$gd=(CmdGateDenied); Tok $true; RunArm "B3-capscope"  ":workspace" "test_bench.py"  "O" $gd     # (3) CapScope-style: cmd gated, token still read directly
Tok $false;              RunArm "B4-broker"           ":workspace" "test_broker.py" "O" "n/a"   # (4) broker: O denied, token not in env
$gd2=(CmdGateDenied); Tok $false; RunArm "B5-broker+capscope" ":workspace" "test_broker.py" "O" $gd2  # (5) combined
Tok $false;              RunArm "U-broker-utility"     ":workspace" "test_broker.py" "W" "n/a"   # utility: W allowed (same-project)
Tok $false;              RunArm "C0-notoken"          ":workspace" "test_bench.py"  "O" "n/a"   # control: W never authenticated
Tok $true; Tok $false;   RunArm "C3-removed"          ":workspace" "test_bench.py"  "O" "n/a"   # control: W state removed (deleted)
Start-Sleep -Milliseconds 800

# ===== aggregate ground truth by nonce =====
$reach=@{}; $bup=@{}
if(Test-Path "$OUT\access_log.jsonl"){ Get-Content "$OUT\access_log.jsonl" | %{ if($_){ try{ $e=$_|ConvertFrom-Json; if($e.cross_project_access -eq $true){ $reach[[string]$e.nonce]=$true } }catch{} } } }
if(Test-Path "$OUT\broker_log.jsonl"){ Get-Content "$OUT\broker_log.jsonl" | %{ if($_){ try{ $e=$_|ConvertFrom-Json; $bup[[string]$e.nonce]="$($e.decision)/$($e.upstream)" }catch{} } } }
$rows=$rows | %{ $_ | Add-Member -NotePropertyName resource_reach -NotePropertyValue ([bool]$reach[[string]$_.nonce]) -PassThru }
$rows=$rows | %{ $_ | Add-Member -NotePropertyName broker_upstream -NotePropertyValue ([string]$bup[[string]$_.nonce]) -PassThru }

if($srv){ Stop-Process -Id $srv.Id -Force -EA SilentlyContinue }
if($brk){ Stop-Process -Id $brk.Id -Force -EA SilentlyContinue }
Write-Host "[def] servers stopped"

$sum="$OUT\defense_summary.txt"
"=== EXP-1 broker (sec3) + EXP-2 baselines (sec4.2). resource_reach = eff_O(W)>B_O confirmed by honeytoken server. ===" | Tee-Object $sum
$rows | Select arm,profile,project,resource_reach,token_read,broker_decision,cmd_denied,broker_upstream,exit,nonce | Format-Table -AutoSize | Out-String | Tee-Object $sum -Append
@(
 "Read guide:",
 " - B1-default  : reach=TRUE  => product default leaks cross-project (baseline).",
 " - B2-isolation: reach=FALSE => per-project store blocks it (token not reachable by O).",
 " - B3-capscope : cmd_denied=True BUT reach=TRUE => command gate != substrate authority (CapScope's own limit).",
 " - B4-broker   : reach=FALSE, broker_decision=deny, token_read=False => broker closes the leak (sec3 contribution).",
 " - U-utility   : broker_decision=allow, broker_upstream=allow/200 => same-project use still works (R5 utility preserved).",
 " - C0/C3       : reach=FALSE => causal control (leak tied to W's authentication state).",
 "Note: 0 reach is not proof of complete mediation; only the git resource path is demonstrated (state protocol limits)."
) -join "`n" | Tee-Object $sum -Append
Write-Host "[def] done -> $sum"
