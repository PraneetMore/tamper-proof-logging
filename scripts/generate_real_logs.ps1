# ============================================================
# 🔴 REAL LOG GENERATOR - Windows
# ============================================================
# This script performs ACTUAL Windows actions that generate
# REAL Event Logs. These are NOT test data.
# ============================================================

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "🔴 REAL LOG GENERATOR - Windows" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "📊 This script performs actual system actions" -ForegroundColor Yellow
Write-Host "🟢 Generated logs are REAL (collected by Event Log)" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan

$TOTAL_ACTIONS = 0
$ITERATIONS = 10

Write-Host "`n📊 Performing $ITERATIONS iterations of real system actions..."

for ($i = 1; $i -le $ITERATIONS; $i++) {
    Write-Host "`nIteration $i..." -ForegroundColor Yellow
    
    # Action 1: REAL process creation (Event ID 4688)
    Write-Host "  Starting Notepad..." -ForegroundColor Gray
    Start-Process notepad.exe -WindowStyle Hidden
    Start-Sleep -Milliseconds 500
    $TOTAL_ACTIONS++
    
    # Action 2: REAL process creation (Event ID 4688)
    Write-Host "  Starting Calculator..." -ForegroundColor Gray
    Start-Process calc.exe -WindowStyle Hidden
    Start-Sleep -Milliseconds 500
    $TOTAL_ACTIONS++
    
    # Action 3: REAL process creation (Event ID 4688)
    Write-Host "  Starting Command Prompt..." -ForegroundColor Gray
    Start-Process cmd.exe -WindowStyle Hidden
    Start-Sleep -Milliseconds 500
    $TOTAL_ACTIONS++
    
    # Action 4: REAL file access
    Write-Host "  Accessing files..." -ForegroundColor Gray
    Get-Content C:\Windows\System32\drivers\etc\hosts -ErrorAction SilentlyContinue | Out-Null
    $TOTAL_ACTIONS++
    
    # Action 5: REAL registry access
    Write-Host "  Accessing registry..." -ForegroundColor Gray
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue | Out-Null
    $TOTAL_ACTIONS++
    
    Write-Host "  ✅ Completed iteration $i ($($i * 5) actions)" -ForegroundColor Green
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "✅ REAL Log Generation Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "📊 Total Actions Performed: $TOTAL_ACTIONS" -ForegroundColor Yellow
Write-Host "`n📊 Check Windows Event Logs:" -ForegroundColor Yellow
Write-Host "   Open Event Viewer → Windows Logs → Security" -ForegroundColor Gray
Write-Host "   Look for Event IDs: 4624, 4625, 4672, 4688, 4720"
Write-Host "`n🔄 Now collect REAL logs with:" -ForegroundColor Yellow
Write-Host "   python -m src.logger.collector --minutes 5" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan
