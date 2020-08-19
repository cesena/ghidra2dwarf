@echo off

SET BINARY_PATH=%1
SET BINARY=%2

echo %BINARY_PATH%
echo %BINARY%

MOVE %TEMP%\debug_info %BINARY_PATH%\.debug_info
MOVE %TEMP%\debug_abbrev %BINARY_PATH%\.debug_abbrev
MOVE %TEMP%\debug_line %BINARY_PATH%\.debug_line
mv %BINARY%.c %BINARY_PATH%
cd %BINARY_PATH%
COPY  %BINARY% %BINARY%.sym.exe
