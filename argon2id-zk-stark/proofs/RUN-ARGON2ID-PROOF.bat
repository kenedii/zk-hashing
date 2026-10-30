@echo off
title Argon2id STARK proof (leave open)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-argon2id-proof.ps1"
echo.
type "%~dp0argon2id-run.log"
pause
