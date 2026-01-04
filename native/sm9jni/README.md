## SM9 JNI（sm9jni.dll）

本目录提供一个 **JNI 动态库骨架**，用于给 `bc-tool` 的 **SM9 页面**提供底层实现。

### 1. Java 侧约定（已实现）

Java JNI 接口在：
- `src/main/java/alg/bc/sm9/Sm9Native.java`
- `src/main/java/alg/bc/sm9/Sm9JniLoader.java`

动态库命名约定：
- Windows：`sm9jni.dll`

加载目录约定（任一即可）：
- `./sm9jni.dll`
- `./lib/sm9jni.dll`（推荐，和 `bc-tool.exe` 同级）

### 2. C 接口约定

本骨架导出 JNI 方法名与 Java `Sm9Native` 完全对应：
- `kgcGenerateMasterKeyPair(purpose)`：返回 `byte[][] {msk, mpk}`
- `kgcDeriveUserPrivateKey(purpose, msk, userIdUtf8)`
- `encrypt(mpkEnc, userIdUtf8, plaintext)`
- `decrypt(skEnc, userIdUtf8, ciphertext)`
- `sign(skSign, userIdUtf8, message)`
- `verify(mpkSign, userIdUtf8, message, signature)`：返回 `jboolean`

> 目前 `sm9jni.c` 仅提供**可编译的 stub**（会抛异常提示“未实现”）。  
> 你需要在这里对接 GmSSL 或你的 SM9 C 实现，把真正的算法填进去。

### 3. Windows 构建（CMake）

准备：
- 安装 CMake
- 准备编译器：
  - MSVC（Visual Studio）或 MinGW
- 设置 `JAVA_HOME` 指向 JDK（能找到 `include/jni.h`）
- 设置 `GmSSL_ROOT` 指向 GmSSL 安装目录（包含 `include/` 和 `lib/`）
  - 若你按默认方式安装到 `C:\Program Files\GmSSL`，可不设置（脚本会默认用该目录）

构建（示例）：

```bat
cd native\sm9jni
mkdir build
cd build
cmake -G "NMake Makefiles" -DJAVA_HOME=%JAVA_HOME% -DGmSSL_ROOT=%GmSSL_ROOT% ..
cmake --build . --config Release
```

输出：
- `build\sm9jni.dll`

把它拷贝到：
- `dist\lib\sm9jni.dll`（或 exe 同级的 `lib\sm9jni.dll`）


