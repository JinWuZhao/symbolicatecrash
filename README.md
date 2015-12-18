# symbolicatecrash
symbolicatecrash by python.

### 使用python写的仿苹果symbolicatecrash工具。

#### 特性：
##### 1.可以根据应用程序的符号文件以及iOS系统库的符号文件解析崩溃栈，比Xcode中的perl原版更稳定
##### 2.模块化的程序结构，用Package封装相关功能，提供扩展接口以用来二次开发

#### 限制：
##### 1.暂时只可以符号化PLCrashReporter生成的崩溃日志，针对_Report Version:104_。
