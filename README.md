# ohos_softbus_lite_read

OpenHarmony2.0轻量级分布式软总线代码阅读

## 目录结构

/foundation/communication/softbus_lite/
├── authmanager         #提供设备认证机制和设备知识库管理。
├── discovery           #提供基于coap协议的设备发现机制。
├── os_adapter          #提供操作系统接口适配层
├── trans_service       #提供认证和传输通道。
├── interfaces          #接口文档
└── note                #我的笔记

## 功能

1.  **设备发现**--对应\\interfaces\kits\discovery\discovery_service.h

    用户使用发现功能时，需要保证发现端设备与被发现端设备在同一个局域网内，并且互相能收到对方以下流程的报文。

    （1）发现端设备，发起discover请求后，使用coap协议在局域网内发送广播。

    （2）被发现端设备使用PublishService接口发布服务，接收端收到广播后，发送coap协议单播给发现端。

    （3）发现端设备收到报文会更新设备信息。

2.  **传输**--对应\\interfaces\kits\transport\session.h

软总线提供统一的基于Session的传输功能，业务可以通过sessionId收发数据或获取其相关基本属性。当前本项目只实现被动接收Session连接的功能，业务可根据自身需要及Session自身属性判断是否接受此Session，如不接受，可以主动拒绝此连接。本项目暂未提供打开Session的相关能力。