@echo off
rem Build both lab targets. Run from a Developer Command Prompt, or use
rem build_lab.ps1 which locates the toolchain for you.
setlocal
if not defined VCINSTALL (
  set "VCINSTALL=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools"
)
if not exist "%VCINSTALL%\VC\Auxiliary\Build\vcvars64.bat" (
  echo Could not find vcvars64.bat under "%VCINSTALL%".
  exit /b 1
)
cd /d "%~dp0"
if not exist obj64 mkdir obj64
if not exist obj32 mkdir obj32

rem /OPT:NOICF stops the linker folding identical functions together, which
rem otherwise leaves marker() and apply_damage() as jmp thunks and moves the
rem code the tests look for somewhere else.
call "%VCINSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /W3 /O2 /Zi /D_CRT_SECURE_NO_WARNINGS lab_target.c /Fe:lab_target.exe /Fo:obj64\ /link /DEBUG /OPT:NOICF user32.lib
if errorlevel 1 exit /b 1
echo Built lab_target.exe ^(x64^)

call "%VCINSTALL%\VC\Auxiliary\Build\vcvars32.bat" >nul
if errorlevel 1 (
  echo Skipping the 32-bit build: vcvars32.bat is not installed.
  exit /b 0
)
cl /nologo /W3 /O2 /Zi /D_CRT_SECURE_NO_WARNINGS lab_target.c /Fe:lab_target32.exe /Fo:obj32\ /link /DEBUG /OPT:NOICF user32.lib
if errorlevel 1 exit /b 1
echo Built lab_target32.exe ^(x86^)
