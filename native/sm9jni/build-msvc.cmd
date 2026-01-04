@echo off
setlocal EnableDelayedExpansion

REM ------------------------------------------------------------
REM Ensure MSVC + Windows SDK environment is initialized
REM (rc.exe/mt.exe are required for CMake try-compile on Windows)
REM ------------------------------------------------------------
set "NEED_VSENV="
where rc >nul 2>nul || set "NEED_VSENV=1"
where mt >nul 2>nul || set "NEED_VSENV=1"

if defined NEED_VSENV (
  REM 1) Try vswhere (if present)
  set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
  if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%i"
  )

  REM 2) Fallback: probe common VS install locations across drives
  if "!VSINSTALL!"=="" (
    for %%D in (C D E F G H I J K) do (
      if "!VSINSTALL!"=="" if exist "%%D:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" set "VSINSTALL=%%D:\Program Files\Microsoft Visual Studio\2022\Community"
      if "!VSINSTALL!"=="" if exist "%%D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" set "VSINSTALL=%%D:\Program Files\Microsoft Visual Studio\2022\Professional"
      if "!VSINSTALL!"=="" if exist "%%D:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" set "VSINSTALL=%%D:\Program Files\Microsoft Visual Studio\2022\Enterprise"
      if "!VSINSTALL!"=="" if exist "%%D:\Program Files (x86)\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" set "VSINSTALL=%%D:\Program Files (x86)\Microsoft Visual Studio\2022\Community"
      if "!VSINSTALL!"=="" if exist "%%D:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" set "VSINSTALL=%%D:\Program Files (x86)\Microsoft Visual Studio\2022\Professional"
      if "!VSINSTALL!"=="" if exist "%%D:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" set "VSINSTALL=%%D:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise"
    )
  )

  if not "!VSINSTALL!"=="" (
    call "!VSINSTALL!\Common7\Tools\VsDevCmd.bat" -no_logo -arch=x64 -host_arch=x64
  ) else (
    echo [WARN] VS installation not found automatically. If build fails, run this script from "Developer Command Prompt for VS".
  )
)

where rc >nul 2>nul || (echo [ERROR] rc.exe not found. Please install Windows 10/11 SDK and/or run from VS Developer Command Prompt. & exit /b 1)
where mt >nul 2>nul || (echo [ERROR] mt.exe not found. Please install Windows 10/11 SDK and/or run from VS Developer Command Prompt. & exit /b 1)

if "%JAVA_HOME%"=="" (
  echo JAVA_HOME is not set.
  exit /b 1
)

if "%GmSSL_ROOT%"=="" (
  set "GmSSL_ROOT=C:\Program Files\GmSSL"
)

set BUILD_DIR=%~dp0build
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

set "PATH=%~dp0..\tools\cmake\cmake-3.29.6-windows-x86_64\bin;%PATH%"

pushd "%BUILD_DIR%"
cmake -G "NMake Makefiles" -DJAVA_HOME="%JAVA_HOME%" -DGmSSL_ROOT="%GmSSL_ROOT%" ..
if errorlevel 1 exit /b 1
cmake --build . --config Release
popd

echo.
echo Built: %BUILD_DIR%\sm9jni.dll
echo Copy it to: ^<bc-tool.exe dir^>\lib\sm9jni.dll
endlocal


