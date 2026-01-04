@echo off
setlocal

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


