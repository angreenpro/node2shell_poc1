<#
.SYNOPSIS
    Don dep moi truong Lab CVE-2026-111497 tren Windows Docker
#>
Write-Host "[*] Dang dung va xoa toan bo container Lab..." -ForegroundColor Yellow
docker compose down -v --remove-orphans
Write-Host "[+] Da don dep hoan tat va giai phong tai nguyen RAM / Port." -ForegroundColor Green