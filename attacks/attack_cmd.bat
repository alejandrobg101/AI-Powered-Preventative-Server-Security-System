@echo off
echo ============================================================
echo   WINDOWS CMD ATTACK SIMULATOR
echo   Target: %1
echo ============================================================
echo.

if "%1"=="" (
    echo Usage: attack_cmd.bat YOUR_IP_ADDRESS
    exit /b
)

set TARGET=%1

:: ─────────────────────────────────────────
:: ATTACK 1 - ICMP Flood
:: ─────────────────────────────────────────
echo [*] Attack 1 - ICMP Flood
for /f "tokens=*" %%t in ('powershell -Command "Get-Date -Format \"yyyy-MM-dd HH:mm:ss\""') do set START=%%t
echo     Start: %START%
for /l %%i in (1,1,500) do ping %TARGET% -n 1 -l 65500 -w 1 >nul
for /f "tokens=*" %%t in ('powershell -Command "Get-Date -Format \"yyyy-MM-dd HH:mm:ss\""') do set END=%%t
echo     End:   %END%
echo.
echo     Copy into RAW_ATTACKS:
echo     { "name": "Attack 1 - ICMP Flood", "start": "%START%", "end": "%END%" },
echo.
echo Press any key for next attack...
pause >nul

:: ─────────────────────────────────────────
:: ATTACK 2 - ICMP Parallel Burst
:: ─────────────────────────────────────────
echo [*] Attack 2 - Parallel ICMP Burst
for /f "tokens=*" %%t in ('powershell -Command "Get-Date -Format \"yyyy-MM-dd HH:mm:ss\""') do set START=%%t
echo     Start: %START%
for /l %%i in (1,1,200) do start /b ping %TARGET% -n 1 -l 65500 -w 1 >nul
timeout /t 10 /nobreak >nul
for /f "tokens=*" %%t in ('powershell -Command "Get-Date -Format \"yyyy-MM-dd HH:mm:ss\""') do set END=%%t
echo     End:   %END%
echo.
echo     Copy into RAW_ATTACKS:
echo     { "name": "Attack 2 - Parallel ICMP Burst", "start": "%START%", "end": "%END%" },
echo.
echo Press any key for next attack...
pause >nul

:: ─────────────────────────────────────────
:: ATTACK 3 - TCP Port Scan
:: ─────────────────────────────────────────
echo [*] Attack 3 - TCP Port Scan
for /f "tokens=*" %%t in ('powershell -Command "Get-Date -Format \"yyyy-MM-dd HH:mm:ss\""') do set START=%%t
echo     Start: %START%
powershell -Command "1..1024 | ForEach-Object { try { $c = New-Object Net.Sockets.TcpClient; $c.ConnectAsync('%TARGET%', $_).Wait(10) | Out-Null; $c.Close() } catch {} }"
for /f "tokens=*" %%t in ('powershell -Command "Get-Date -Format \"yyyy-MM-dd HH:mm:ss\""') do set END=%%t
echo     End:   %END%
echo.
echo     Copy into RAW_ATTACKS:
echo     { "name": "Attack 3 - TCP Port Scan", "start": "%START%", "end": "%END%" },
echo.
echo Press any key for next attack...
pause >nul

:: ─────────────────────────────────────────
:: ATTACK 4 - UDP Burst
:: ─────────────────────────────────────────
echo [*] Attack 4 - UDP Burst
for /f "tokens=*" %%t in ('powershell -Command "Get-Date -Format \"yyyy-MM-dd HH:mm:ss\""') do set START=%%t
echo     Start: %START%
powershell -Command "$c = New-Object Net.Sockets.UdpClient; $b = New-Object byte[] 1024; 1..300 | ForEach-Object { try { $c.Send($b, $b.Length, '%TARGET%', (Get-Random -Min 1 -Max 65535)) } catch {} }; $c.Close()"
for /f "tokens=*" %%t in ('powershell -Command "Get-Date -Format \"yyyy-MM-dd HH:mm:ss\""') do set END=%%t
echo     End:   %END%
echo.
echo     Copy into RAW_ATTACKS:
echo     { "name": "Attack 4 - UDP Burst", "start": "%START%", "end": "%END%" },
echo.
echo Press any key for next attack...
pause >nul

:: ─────────────────────────────────────────
:: ATTACK 5 - HTTP Connection Burst
:: ─────────────────────────────────────────
echo [*] Attack 5 - HTTP Connection Burst
for /f "tokens=*" %%t in ('powershell -Command "Get-Date -Format \"yyyy-MM-dd HH:mm:ss\""') do set START=%%t
echo     Start: %START%
powershell -Command "1..200 | ForEach-Object { try { $r = [Net.WebRequest]::Create('http://%TARGET%'); $r.Timeout = 100; $r.GetResponse() } catch {} }"
for /f "tokens=*" %%t in ('powershell -Command "Get-Date -Format \"yyyy-MM-dd HH:mm:ss\""') do set END=%%t
echo     End:   %END%
echo.
echo     Copy into RAW_ATTACKS:
echo     { "name": "Attack 5 - HTTP Connection Burst", "start": "%START%", "end": "%END%" },
echo.
echo [+] All attacks complete.
pause
