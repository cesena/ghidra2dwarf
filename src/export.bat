@echo off

SET BINARY_PATH=%~1
SET %~1BINARY=%~2
echo %BINARY_PATH%
echo %BINARY%
mv \tmp\debug_info %BINARY_PATH%\.debug_info
mv \tmp\debug_abbrev %BINARY_PATH%\.debug_abbrev
mv \tmp\debug_line %BINARY_PATH%\.debug_line
mv %BINARY%%CD%c %BINARY_PATH%
cd %BINARY_PATH%
COPY  %BINARY% %BINARY%%CD%sym.exe
objcopy.exe --add-section %CD%debug_info=%CD%debug_info %BINARY%%CD%sym.exe
objcopy.exe --add-section %CD%debug_line=%CD%debug_line %BINARY%%CD%sym.exe
objcopy.exe --add-section %CD%debug_abbrev=%CD%debug_abbrev %BINARY%%CD%sym.exe
