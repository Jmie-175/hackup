@echo off
echo PhishGuard Browser Switcher
echo ===========================
set /p browser="Which browser are you using? (chrome/firefox): "

if /i "%browser%"=="chrome" (
    copy manifest.chrome.json manifest.json /y
    echo [SUCCESS] Switched to Chrome configuration.
) else if /i "%browser%"=="firefox" (
    copy manifest.firefox.json manifest.json /y
    echo [SUCCESS] Switched to Firefox configuration.
) else (
    echo [ERROR] Invalid choice. Please type 'chrome' or 'firefox'.
)
pause
