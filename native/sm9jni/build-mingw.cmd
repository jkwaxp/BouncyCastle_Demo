@echo off
setlocal

if "%JAVA_HOME%"=="" (
  echo JAVA_HOME is not set.
  exit /b 1
)

set BUILD_DIR=%~dp0build-mingw
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

pushd "%BUILD_DIR%"
cmake -G "MinGW Makefiles" -DJAVA_HOME="%JAVA_HOME%" ..
if errorlevel 1 exit /b 1
cmake --build . --config Release
popd

echo.
echo Built: %BUILD_DIR%\sm9jni.dll
echo Copy it to: ^<bc-tool.exe dir^>\lib\sm9jni.dll
endlocal


