<#
.SYNOPSIS
    Khoi dong Lab CVE-2026-111497 tren Windows Docker Desktop
#>
$ErrorActionPreference = "Stop"

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  KHOI DONG LAB CVE-2026-111497 TREN WINDOWS DOCKER DESKTOP   " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# 1. Kiem tra Docker Engine
try {
    $null = docker version
} catch {
    Write-Host "[!] LOI: Docker Desktop chua duoc bat hoac chua hoan tat khoi dong." -ForegroundColor Red
    Write-Host "    Vui long mo Docker Desktop tren Windows va doi bieu tuong chuyen sang mau xanh." -ForegroundColor Yellow
    exit 1
}

# 2. Build va khoi chay cac container
Write-Host "[*] Dang build va khoi dong cac container..." -ForegroundColor Green
docker compose up -d --build

# 3. Thong bao dich vu
Write-Host "`n[+] He thong Lab da san sang hoat dong!" -ForegroundColor Green
Write-Host "    - Nginx WAF (Cong kiem thu chinh) : http://localhost:8085" -ForegroundColor White
Write-Host "    - Target Node.js (Bypass WAF)     : http://localhost:3000" -ForegroundColor White
Write-Host "    - Web UI Console truc quan        : http://localhost:8088 (hoac :3000)" -ForegroundColor White
Write-Host "`n[*] Goi y: Chay .\run_lab_tests.ps1 de bat dau cac kich ban kiem thu." -ForegroundColor Yellow