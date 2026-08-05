@echo off
setlocal enabledelayedexpansion

echo Building clover.exe...
go build -ldflags="-s -w" -o clover.exe .
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo Done.
