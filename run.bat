@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem Запуск из исходников на Windows: двойной клик по этому файлу.
rem Готовому приложению он не нужен: exe со страницы релизов запускается сам.

rem Ищем интерпретатор, в котором есть customtkinter.
set "PY=py"
where py >nul 2>nul || set "PY=python"
where %PY% >nul 2>nul || goto :nopython
%PY% -c "import customtkinter" >nul 2>nul && goto :run

if /i "%PY%"=="py" (set "ALT=python") else (set "ALT=py")
where %ALT% >nul 2>nul || goto :nodeps
%ALT% -c "import customtkinter" >nul 2>nul || goto :nodeps
set "PY=%ALT%"
goto :run

:run
%PY% main.py %*
if errorlevel 1 (
    echo.
    echo [ошибка] Приложение завершилось с ошибкой. Текст выше.
    goto :fail
)
exit /b 0

:nopython
echo [ошибка] Python не найден.
echo Поставьте Python 3.11+ с python.org либо скачайте готовый exe:
echo     страница Releases на GitHub, файл SmartPCAPParser.exe
goto :fail

:nodeps
echo [нужна библиотека] В Python нет customtkinter.
echo Установите её одной командой:
echo     %PY% -m pip install -r requirements.txt
echo Либо скачайте готовый exe без Python:
echo     страница Releases на GitHub, файл SmartPCAPParser.exe
goto :fail

:fail
echo.
pause
exit /b 1
