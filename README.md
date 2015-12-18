# symbolicatecrash
symbolicatecrash by python.
version: 1.0.0

### 使用python写的仿苹果symbolicatecrash工具。

##### 特性：
1.可以根据应用程序的符号文件以及iOS系统库的符号文件解析崩溃栈，不使用spotlight搜索文件，比Xcode中的perl原版更稳定
2.模块化的程序结构，用Package封装相关功能，提供扩展接口以用来二次开发

##### 限制：
1.暂时只可以符号化PLCrashReporter生成的崩溃日志，针对_Report Version:104_。

##### 使用方法：
1.请检查"~/Library/Developer/Xcode/iOS DeviceSupport/"目录下是否存在各系统版本的符号文件（如："9.1 (13B143)"等），如果不存在，那么您需要去收集一些了（方法稍后描述），否则将无法符号化iOS系统库的调用栈。
2.检查您的应用程序的符号文件路径并记录下来, 通常在编译导出后的archive文件中，名为"/path/xxx.app.dSYM"。
3.检查您的崩溃日志路径并记录下来，如"/path/xxx.crash"。
4.打开终端进入该项目根目录：cd /path/symbolicatecrash，键入命令：./symbolicatecrash /path/xxx.crash /path/xxx.app.dSYM -o /path/symbolic_log.crash

##### 注意事项：
1.iOS系统库的调用栈无法解析？
可能是您的Mac上不存在对应版本的符号文件，只有iOS系统版本和cpu架构版本都对应上才能正确解析。
2.如何收集iOS系统库的符号文件？
在Mac上打开Xcode程序，将iOS设备连接到Mac上，在Xcode左上角target后面选择连接的设备，会看到Xcode上方中间的状态栏上会有Symbolicating的提示，当进度完成时符号文件就已经取到了。注意这个过程只能取得连接设备上的对应cpu架构及iOS系统版本的符号文件，如连接的设备为armv7s iOS8.1，则只能取到iOS8.1版本在armv7s架构上的符号文件，如果cpu架构为arm64则取到的符号文件中会包含arm64和armv7s两者。当然也可以去其他的Mac上拷贝符号文件，这样更容易。
##### 3.遇到其它问题？
请马上提交issue，告诉情况或者提交改进建议。
