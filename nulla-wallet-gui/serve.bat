@echo off
echo Starting Nulla Wallet GUI Server...
echo.
echo Wallet will be available at: http://localhost:8080
echo Make sure your Nulla node is running with: cargo run --bin nulla --rpc 127.0.0.1:27447
echo.
echo Press Ctrl+C to stop the server
echo.

REM Try Python first
where python >nul 2>nul
if %ERRORLEVEL% == 0 (
    echo Using Python HTTP server...
    python -m http.server 8080
    goto :end
)

REM Try Node.js
where node >nul 2>nul
if %ERRORLEVEL% == 0 (
    echo Using Node.js HTTP server...
    npx http-server -p 8080 --cors
    goto :end
)

REM Try PHP
where php >nul 2>nul
if %ERRORLEVEL% == 0 (
    echo Using PHP built-in server...
    php -S localhost:8080
    goto :end
)

echo ERROR: No web server found!
echo Please install Python, Node.js, or PHP to run the wallet GUI
echo.
echo Or manually open: file://%CD%\index.html
pause

:end
