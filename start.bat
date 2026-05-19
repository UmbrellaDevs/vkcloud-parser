@echo off
chcp 65001 >nul
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo [error] Node.js не найден в PATH.
  echo Установите Node.js LTS: https://nodejs.org/
  pause
  exit /b 1
)

cd launcher
call npm install
if errorlevel 1 (
  echo [error] npm install завершился с ошибкой.
  pause
  exit /b 1
)

echo.
echo [run] Открываю панель: http://localhost:3847
echo [info] Если порт уже занят, возможно лаунчер уже запущен.
echo.
node server.js
echo.
echo [exit] Лаунчер остановлен или завершился с ошибкой.
pause
