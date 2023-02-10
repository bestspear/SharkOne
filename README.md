# SharkOneCS

## 版本

bata.0.0 测试版

## 一些说明

- 基于CobaltStrike4.5二开完成
- SharkOne的主要功能是将beacon代码可视化，其实是为了方便自己也方便其他做这方面的二次开发
- teamserver验证标识是将48879改成了其他标志并且验证错误会返回其他内容并记录ip
- 其他的一些beacon改了一些零零散散的功能，后面版本主要针对beacon进行一些修改，或者添加删除一些功能
- 支持c2profile
- beacon对c2配置文件的GET/POST url随机访问并在测试中新加了一些httpheader以做混淆，可以到beacon源码参考并修改
- 编译器目前只测试了msvc＋llvm 可以自行在beacon/relaese32/64.bat beacon/start32/64.bat配置ollvm+mingw等其他编译器
- 目前仅支持http、https 后面beacon内容会在以后版本发布
- 造轮子项目，功能主要看个人修改，免杀姿势可以自己对beacon进行修修补补

## 文件说明

|          文件名           |                             说明                             |
| :-----------------------: | :----------------------------------------------------------: |
|          beacon           | beacon源码目录，beaconMain.cpp为源码，其余为组件函数源码，start32/64.bat为编译组件脚本，release32/64.bat为编译主模块脚本 |
|           ttlog           |              为标志日志目录，里面并没什么好东西              |
|   SharkCS4_5_server.jar   |                       teamserver jar包                       |
|   SharkCS4_5_client.jar   |                         client jar包                         |
| teamserver.bat/teamserver |                      teamserver启动脚本                      |
|     cobaltstrike.auth     |             license文件涉及ssl密钥可以按需求修改             |
|         其他文件          |           其他文件为一些启动bat脚本和一些别的文件            |



## 环境配置

由于项目中teamserver内置编译，所以需要有对应的编译环境

目前测试的环境为

teamserver:

​	操作系统：Windows10

​	编译器版本：clang15.0.5

​	链接器版本：x86_64-pc-windows-msvc

​	java版本：java 17.0.2 2022-01-18 LTS

client:

​	操作系统：Windows10

​	java版本：java 17.0.2 2022-01-18 LTS

Linux需要额外配置环境，并且需要msvc的头文件，如果有兴趣可以Linux部署踩下坑

## 二开说明

1. beacon可视化，teamserver启动生成beacon逻辑，现在直接在源码中修改即可
2. 内置llvm编译器，每次listener创建或重启时都对beacon进行重新编译
3. 去除beacon端main函数起始时申请的4096c2profile配置操作
4. 新增beacon对teamserver心跳或命令执行的随机c2profile配置访问
5. 新增远程编译beacon组件
6. 新增beacon端bof的异常处理，以前的bof比较脆弱，针对这部分进行了修复
7. 新增beacon get或post随机访问c2profile配置中的所有字符串路径
8. 增加teamserver防爆破，访问次数为一个小时限定一百次
9. 增加teamserver防检测
10. 增加teamserver对client的登录flag，并增加flag错误返回403并记录ip
11. 修复cve-2022-39197漏洞