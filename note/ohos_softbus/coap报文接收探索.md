# lite软总线层库COAP报文接收探索

> discovery\coap\source\coap_discover.c下的CreateCoapListenThread函数会创建了CoapReadHandle线程，处理COAP_DEFAULT_PORT端口上的UDP socket的数据（也就是基于COAP协议的discover广播消息）

结合我们之前的日志如下：

```c
enter SoftBus Task
//discovery\discovery_service\source\common_info_manager.c InitLocalDeviceInfo成功
[DISCOVERY] InitLocalDeviceInfo ok
    
//discovery\coap\source\coap_discover.c  CoapInitWifiEvent成功
[DISCOVERY] CoapInitWifiEvent
    
//discovery\coap\source\coap_discover.c  CoapWriteMsgQueue成功
[DISCOVERY] CoapWriteMsgQueue
    
//discovery\discovery_service\source\discovery_service.c  InitService成功
[DISCOVERY] InitService ok
    
//PublishService函数成功
[DISCOVERY] PublishCallback publishId=233, result=0
publish succeeded, publishId = 233
PublishService init success
CoapGetIp = 192.168.137.194
StartSessionServer successed!

//trans_service\source\libdistbus\auth_conn_manager.c WaitProcess启动
[TRANS] WaitProcess begin

//trans_service\source\libdistbus\auth_conn_manager.c StartListener成功
[TRANS] StartListener ok
    
//trans_service\source\libdistbus\tcp_session_manager.c  SelectSessionLoop启动
[TRANS] SelectSessionLoop begin

//authmanager\source\bus_manager.c StartBus成功
[AUTH] StartBus ok

//discovery\coap\source\coap_discover.c CoapReadHandle启动
[DISCOVERY] CoapReadHandle coin select begin
hiview init success.
```



## 侦测广播包

### COAP监听线程,CoapReadHandle



```c
static void CoapReadHandle(unsigned int uwParam1, unsigned int uwParam2, unsigned int uwParam3, unsigned int uwParam4)
{
    (void)uwParam1;
    (void)uwParam2;
    (void)uwParam3;
    (void)uwParam4;
    int ret;
    fd_set readSet;
    int serverFd = GetCoapServerSocket(); //获得g_serverFd，由CoapInitSocket初始化
    SOFTBUS_PRINT("[DISCOVERY] CoapReadHandle coin select begin\n");
    while (g_terminalFlag)
    {
        FD_ZERO(&readSet);
        FD_SET(serverFd, &readSet);
        ret = select(serverFd + 1, &readSet, NULL, NULL, NULL);
        if (ret > 0)
        {
            //如果侦测到了包会调用HandleReadEvent
            if (FD_ISSET(serverFd, &readSet))
            {
                HandleReadEvent(serverFd);
            }
        }
        else
        {
            SOFTBUS_PRINT("[DISCOVERY]ret:%d,error:%d\n", ret, errno);
        }
    }
    SOFTBUS_PRINT("[DISCOVERY] CoapReadHandle exit\n");
}
```



通过这里我们可以判断出，系统到底有没有接收到相应的信息。

经过我们的测试，可以收到报文。

![](https://picgo-1305367394.cos.ap-beijing.myqcloud.com/picgo/202110231545565.png)

### select相关API介绍与使用

> [Linux编程之select - Madcola - 博客园 (cnblogs.com)](https://www.cnblogs.com/skyfsm/p/7079458.html)

![img](https://picgo-1305367394.cos.ap-beijing.myqcloud.com/picgo/202110231514145.png)

如上所示，用户首先将需要进行IO操作的socket添加到select中，然后阻塞等待select系统调用返回。当数据到达时，socket被激活，select函数返回。用户线程正式发起read请求，读取数据并继续执行。

从流程上来看，使用select函数进行IO请求和同步阻塞模型没有太大的区别，甚至还多了添加监视socket，以及调用select函数的额外操作，效率更差。但是，使用select以后最大的优势是**用户可以在一个线程内同时处理多个socket的IO请求**。用户可以注册多个socket，然后不断地调用select读取被激活的socket，即可达到在同一个线程内同时处理多个IO请求的目的。而在同步阻塞模型中，必须通过多线程的方式才能达到这个目的。

```c
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
int select(int maxfdp, fd_set *readset, fd_set *writeset, fd_set *exceptset,struct timeval *timeout);
```

参数说明：

maxfdp：被监听的文件描述符的总数，它比所有文件描述符集合中的文件描述符的最大值大1，因为文件描述符是从0开始计数的；

readfds、writefds、exceptset：分别指向可读、可写和异常等事件对应的描述符集合。

timeout:用于设置select函数的超时时间，即告诉内核select等待多长时间之后就放弃等待。timeout == NULL 表示等待无限长的时间

timeval结构体定义如下

```c
struct timeval
{      
    long tv_sec;   /*秒 */
    long tv_usec;  /*微秒 */   
};
```

返回值：超时返回0;失败返回-1；成功返回大于0的整数，这个整数表示就绪描述符的数目。



这里的几个宏含义解释:

```c
#include <sys/select.h>   
int FD_ZERO(int fd, fd_set *fdset);   //一个 fd_set类型变量的所有位都设为 0
int FD_CLR(int fd, fd_set *fdset);  //清除某个位时可以使用
int FD_SET(int fd, fd_set *fd_set);   //设置变量的某个位置位
int FD_ISSET(int fd, fd_set *fdset); //测试某个位是否被置位
```



## 检测到广播包后

```c
static void HandleReadEvent(int fd)
{
    int socketFd = fd;
    unsigned char *recvBuffer = calloc(1, COAP_MAX_PDU_SIZE + 1);
    if (recvBuffer == NULL)
    {
        return;
    }
    ssize_t nRead;
    //读取socket的内容，返回值为recvfrom返回值,内容见下
    nRead = CoapSocketRecv(socketFd, recvBuffer, COAP_MAX_PDU_SIZE);
    
    if ((nRead == 0) || (nRead < 0 && errno != EAGAIN &&
                         errno != EWOULDBLOCK && errno != EINTR))
    {
        free(recvBuffer);
        return;
    }
	 //创建一个空的标准coap包
    COAP_Packet decodePacket;
    (void)memset_s(&decodePacket, sizeof(COAP_Packet), 0, sizeof(COAP_Packet));
    decodePacket.protocol = COAP_UDP;
    //coap包检查与解码
    COAP_SoftBusDecode(&decodePacket, recvBuffer, nRead);
    //处理解码后的报文,构建发送包并调用函数进行发送
    PostServiceDiscover(&decodePacket);
    free(recvBuffer);
}
```

#### CoapSocketRecv

```c
//discovery\coap\source\coap_socket.c 
int CoapSocketRecv(int socketFd, uint8_t *buffer, size_t length)
{
    if (buffer == NULL || socketFd < 0) {
        return NSTACKX_EFAILED;
    }

    struct sockaddr_in addr;
    socklen_t len = sizeof(struct sockaddr_in);
    (void)memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    int ret = recvfrom(socketFd, buffer, length, 0, (struct sockaddr *)&addr, &len);
    return ret;
}

//其中struct sockaddr_in 参考定义如下（linux下定义）

struct sockaddr_in
{
    __SOCKADDR_COMMON (sin_);   //2 bytes address family, AF_xxx  
    in_port_t sin_port;         //2 bytes e.g. htons(3490)  
    struct in_addr sin_addr;    //4 bytes see struct in_addr, below  

    // 8 bytes zero this if you want to  
    unsigned char sin_zero[sizeof (struct sockaddr) -
               __SOCKADDR_COMMON_SIZE -
               sizeof (in_port_t) -
               sizeof (struct in_addr)];
};
typedef unsigned short int sa_family_t;
#define    __SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family
  
#define __SOCKADDR_COMMON_SIZE    (sizeof (unsigned short int))
typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;
struct in_addr
{
    in_addr_t s_addr;
};
```

<img src="https://picgo-1305367394.cos.ap-beijing.myqcloud.com/picgo/202110231615555.png" alt="image-20211023161550438" style="zoom:67%;" />



#### COAP_SoftBusDecode

```c
//discovery\coap\source\coap_adapter.c
int COAP_SoftBusDecode(COAP_Packet *pkt, const unsigned char *buf, unsigned int bufLen)
{
    int ret;
    if (pkt == NULL || buf == NULL) {
        return -1;
    }

    if (bufLen == 0) {
        return -1;
    }

    if (pkt->protocol != COAP_UDP) {
        return -1;
    }

    ret = COAP_ParseHeader(pkt, buf, bufLen);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    if (pkt->header.ver != COAP_VERSION) {
        return DISCOVERY_ERR_VER_INVALID;
    }

    if (pkt->header.tokenLen > MAX_TOK_LEN) {
        return DISCOVERY_ERR_INVALID_TOKEN_LEN;
    }

    if ((bufLen > HEADER_LEN) && (pkt->header.code == 0)) {
        return DISCOVERY_ERR_INVALID_EMPTY_MSG;
    }

    if (pkt->header.tokenLen == 0) {
        pkt->token.buffer = NULL;
        pkt->token.len = 0;
    } else if ((unsigned int)(pkt->header.tokenLen + HEADER_LEN) > bufLen) {
        return DISCOVERY_ERR_TOKEN_INVALID_SHORT;
    } else {
        pkt->token.buffer = &buf[BUF_OFFSET_BYTE4];
        pkt->token.len = pkt->header.tokenLen;
    }

    ret = COAP_ParseOptionsAndPayload(pkt, buf, bufLen);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    pkt->len = bufLen;
    return DISCOVERY_ERR_SUCCESS;
}
```

#### PostServiceDiscover

```c
//discovery\coap\source\coap_discover.c
void PostServiceDiscover(const COAP_Packet *pkt)
{
    char *remoteUrl = NULL;
    DeviceInfo deviceInfo;

    if (pkt == NULL)
    {
        return;
    }

    (void)memset_s(&deviceInfo, sizeof(deviceInfo), 0, sizeof(deviceInfo));
    ////继续深度解包，涉及到了对报文的解析，之后可以获得发包者信息，填入到了deviceInfo中
    if (GetServiceDiscoverInfo(pkt->payload.buffer, pkt->payload.len, &deviceInfo, &remoteUrl) != NSTACKX_EOK)
    {
        return;
    }

    char wifiIpAddr[NSTACKX_MAX_IP_STRING_LEN];
    (void)memset_s(wifiIpAddr, sizeof(wifiIpAddr), 0, sizeof(wifiIpAddr));
    (void)inet_ntop(AF_INET, &deviceInfo.netChannelInfo.wifiApInfo.ip, wifiIpAddr, sizeof(wifiIpAddr));

    if (remoteUrl != NULL)
    {
        //通过解析到的手机(发现端)的地址，应答服务
        CoapResponseService(pkt, remoteUrl, wifiIpAddr);
        free(remoteUrl);
    }
}

typedef struct DeviceInfo {
    char deviceName[NSTACKX_MAX_DEVICE_NAME_LEN];
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    int deviceType;
    uint16_t portNumber;
    NetChannelInfo netChannelInfo;
    /* Capability data */
    uint32_t capabilityBitmapNum;
    uint32_t capabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM];
    char version[NSTACKX_MAX_HICOM_VERSION];
    uint8_t mode;
    char deviceHash[DEVICE_HASH_LEN];
    char serviceData[NSTACKX_MAX_SERVICE_DATA_LEN];
} DeviceInfo;
```



## 修改日志

- ce91aaa545102f733607219a5d48fa940d3b51f0：测试select返回值

  ![image-20211023154509101](https://picgo-1305367394.cos.ap-beijing.myqcloud.com/picgo/202110231545173.png)

  ​		可以检测到报文。

- 65ea0e2f0a875e65bfc205698cfbf93afd3079f1：打印收到的包的基本信息：

  ![image-20211023163046463](https://picgo-1305367394.cos.ap-beijing.myqcloud.com/picgo/202110231630530.png)

- 可以对包的内容完成解析

  ![image-20211023172236044](https://picgo-1305367394.cos.ap-beijing.myqcloud.com/picgo/202110231722154.png)
