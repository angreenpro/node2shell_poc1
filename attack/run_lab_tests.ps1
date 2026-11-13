<#
.SYNOPSIS
    Purple Team Lab Launcher & Automated Test Trigger (.ps1) cho CVE-2026-111497 (Node2Shell)
.DESCRIPTION
    Kich hoat cac lenh kiem thu truc tiep tu Windows PowerShell (su dung Invoke-WebRequest / curl.exe / python)
.EXAMPLE
    .\run_lab_tests.ps1
    .\run_lab_tests.ps1 -Action all
    .\run_lab_tests.ps1 -Action 1
#>

param(
    [string]$Action = "menu",
    [string]$WafUrl = "http://localhost:8080",
    [string]$DirectUrl = "http://localhost:3000",
    [string]$FalcoContainer = "lab-falco-edr"
)

function Write-Banner([string]$Title) {
    Write-Host "`n==========================================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "==========================================================================" -ForegroundColor Cyan
}

function Invoke-RawPost([string]$Url, [hashtable]$Headers, [byte[]]$Bytes) {
    try {
        $resp = Invoke-WebRequest -Uri $Url -Method Post -Headers $Headers -Body $Bytes -UseBasicParsing -ErrorAction Stop
        return @{ Status = [int]$resp.StatusCode; Body = $resp.Content }
    } catch {
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
            return @{ Status = $code; Body = $_.Exception.Message }
        }
        return @{ Status = 0; Body = $_.Exception.Message }
    }
}

function Test-01-Recon {
    Write-Banner "[TEST 01] KIEM TRA PHIEN BAN BINARY NODE.JS & C++ BROTLI"
    try {
        $resp = Invoke-RestMethod -Uri "$DirectUrl/api/info" -Method Get -ErrorAction Stop
        Write-Host "  Node.js Version : $($resp.nodeVersion)" -ForegroundColor Green
        Write-Host "  Brotli Version  : $($resp.brotliVersion)" -ForegroundColor Yellow
        Write-Host "  Zlib Version    : $($resp.zlibVersion)"
    } catch {
        Write-Host "  [FAIL] Khong the ket noi toi $DirectUrl/api/info : $_" -ForegroundColor Red
    }
}

function Test-02-Differential {
    Write-Banner "[TEST 02] KIEM THU VI SAI BE MAT GIAI NEN (0x3b vs 0xff)"
    [byte[]]$validBr = @(0x3b)
    [byte[]]$malBr   = @(0xff)
    $hdrs = @{ "Content-Encoding" = "br"; "Content-Type" = "application/json" }

    Write-Host "1. Gui qua Nginx WAF ($WafUrl/api/upload):" -ForegroundColor White
    $w1 = Invoke-RawPost -Url "$WafUrl/api/upload" -Headers $hdrs -Bytes $validBr
    $w2 = Invoke-RawPost -Url "$WafUrl/api/upload" -Headers $hdrs -Bytes $malBr
    Write-Host "   ├── Goi 0x3b (Valid Empty Brotli) : HTTP $($w1.Status) (Mong doi: 415)"
    Write-Host "   └── Goi 0xff (Malformed Brotli)   : HTTP $($w2.Status) (Mong doi: 415)"

    Write-Host "`n2. Gui truc tiep vao Backend ($DirectUrl/api/upload):" -ForegroundColor White
    $d1 = Invoke-RawPost -Url "$DirectUrl/api/upload" -Headers $hdrs -Bytes $validBr
    $d2 = Invoke-RawPost -Url "$DirectUrl/api/upload" -Headers $hdrs -Bytes $malBr
    Write-Host "   ├── Goi 0x3b (Valid Empty Brotli) : HTTP $($d1.Status) (Mong doi: 200)"
    Write-Host "   └── Goi 0xff (Malformed Brotli)   : HTTP $($d2.Status) (Mong doi: 400)"
}

function Test-03-WafAndDos {
    Write-Banner "[TEST 03] KIEM THU CHOT CHAN WAF (HTTP 415) & CHONG SAP STREAM"
    [byte[]]$validBr = @(0x3b)
    foreach ($variant in @("br", "BR", "gzip, br")) {
        $res = Invoke-RawPost -Url "$WafUrl/api/upload" -Headers @{ "Content-Encoding" = $variant } -Bytes $validBr
        Write-Host "   ├── WAF Test Header 'Content-Encoding: $variant' -> HTTP $($res.Status)"
    }

    Write-Host "`n[*] Gui luong byte hong vao Backend ($DirectUrl/api/upload)..."
    [byte[]]$corrupted = @(0x1b, 0x00, 0x00, 0xff, 0xff)
    $errRes = Invoke-RawPost -Url "$DirectUrl/api/upload" -Headers @{ "Content-Encoding" = "br" } -Bytes $corrupted
    Write-Host "   ├── KQ luong hong : HTTP $($errRes.Status)"

    try {
        $alive = Invoke-WebRequest -Uri "$DirectUrl/api/info" -UseBasicParsing -ErrorAction Stop
        Write-Host "   └── Kiem tra Server con song (/api/info) : HTTP $($alive.StatusCode) [PASS]" -ForegroundColor Green
    } catch {
        Write-Host "   └── [FAIL] Server khong phan hoi sau khi nhan luong byte loi!" -ForegroundColor Red
    }
}

function Test-04-Outbound {
    Write-Banner "[TEST 04] KIEM THU PHOI NHIEM CHIEU RA (OUTBOUND FETCH CLIENT)"
    try {
        $def = Invoke-RestMethod -Uri "$WafUrl/api/webhook-test" -Method Get
        $safe = Invoke-RestMethod -Uri "$WafUrl/api/webhook-test" -Method Get -Headers @{ "x-safe-outbound" = "true" }
        Write-Host "  ├── Mac dinh (Chua loc) : Accept-Encoding = '$($def.clientSentAcceptEncoding)' | Exposed = $($def.exposedToMaliciousBrotliResponse)" -ForegroundColor Yellow
        Write-Host "  └── Che do An toan      : Accept-Encoding = '$($safe.clientSentAcceptEncoding)' | Exposed = $($safe.exposedToMaliciousBrotliResponse)" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Loi khi goi /api/webhook-test : $_" -ForegroundColor Red
    }
}

function Test-05-EdrFalco {
    Write-Banner "[TEST 05] KICH HOAT GIA LAP RCE TELEMETRY & KIEM TRA FALCO LOG"
    try {
        $res = Invoke-RestMethod -Uri "$WafUrl/sim/rce-trigger" -Method Post
        Write-Host "  Phan hoi tu container: $($res.Trim())" -ForegroundColor Green
        Start-Sleep -Seconds 2
        Write-Host "  [*] Truy van log tu container $FalcoContainer..."
        docker logs --tail 25 $FalcoContainer 2>&1 | Select-String -Pattern "NODE2SHELL|CRITICAL"
    } catch {
        Write-Host "  [FAIL] Khong the kich hoat /sim/rce-trigger : $_" -ForegroundColor Red
    }
}

function Invoke-AllTests {
    Test-01-Recon
    Test-02-Differential
    Test-03-WafAndDos
    Test-04-Outbound
    Test-05-EdrFalco
}

if ($Action -ne "menu") {
    switch ($Action) {
        "1"   { Test-01-Recon }
        "2"   { Test-02-Differential }
        "3"   { Test-03-WafAndDos }
        "4"   { Test-04-Outbound }
        "5"   { Test-05-EdrFalco }
        "py"  { python run_all_tests.py }
        "all" { Invoke-AllTests }
        default { Invoke-AllTests }
    }
    exit 0
}

while ($true) {
    Write-Host "`n================ MENU KICH HOAT KIEM THU NODE2SHELL (POWERSHELL) ================" -ForegroundColor Cyan
    Write-Host "  1) Chay Test 01: Kiem tra phien ban Node.js & Brotli"
    Write-Host "  2) Chay Test 02: Kiem thu vi sai 0x3b vs 0xff"
    Write-Host "  3) Chay Test 03: Kiem thu WAF 415 & Chong sap Stream"
    Write-Host "  4) Chay Test 04: Kiem thu Outbound Fetch Header"
    Write-Host "  5) Chay Test 05: Kich hoat RCE Telemetry & Check Falco Log"
    Write-Host "  a) Chay TOAN BO 5 bai test (PowerShell Native)"
    Write-Host "  p) Chay Python Master Test Suite (python run_all_tests.py)"
    Write-Host "  d) Khoi dong Lab Docker (docker compose up -d)"
    Write-Host "  q) Thoat"
    Write-Host "=================================================================================" -ForegroundColor Cyan
    $choice = Read-Host "Chon thao tac [1-5, a, p, d, q]"
    switch ($choice.ToLower()) {
        "1" { Test-01-Recon }
        "2" { Test-02-Differential }
        "3" { Test-03-WafAndDos }
        "4" { Test-04-Outbound }
        "5" { Test-05-EdrFalco }
        "a" { Invoke-AllTests }
        "p" { python run_all_tests.py }
        "d" { docker compose up -d }
        "q" { exit 0 }
        default { Write-Host "Lua chon khong hop le!" -ForegroundColor Yellow }
    }
}
