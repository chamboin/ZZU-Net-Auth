# 郑州大学有线校园网认证

这个项目是为了方便想在寝室多设备使用有线校园网的同学们创立的，提供一个享用有线网络稳定、低延迟和多设备在线的解决方案。

* ## 设计原理

    锐捷客户端会检测系统的网卡数量从而限制认证的电脑开热点共享有线网络，那么有没有办法绕过锐捷客户端呢，答案是肯定的，通过抓包认证过程和后续的数据包可以发现，认证成功后是通过本地定时发送心跳包来维持连接的，并且认证完成后服务端只检测心跳包而不发送其他请求（至少我在校期间是这样，可能以后会有变化吧）。这样我们就可以使用路由器转发电脑的认证包完成认证，之后代替电脑发送心跳包维持。  
    那么为什么不直接使用路由器认证呢？因为我尝试了基于Linux 的认证程序MENTOHUST，无法完成认证，所以就用这个办法曲线救国。同学们可以自行尝试MentoHust是否可以认证。

* ## 使用方法

    首先肯定要有一个充值过了的校园网账号啦，要开通有线网，学校会分配一个固定的IP地址并且要求绑定你终端设备的MAC地址，这个MAC地址绑定你用来认证的设备就可以。  
    然后你需要一个可以运行自定义程序的路由器，比如刷了机的小米路由器、~~两万多的高端路由器~~斐讯、睾贵的阿苏斯等等（仅作举例说明，不作实际推荐）。  
    接下来如果你使用的路由器是MTK7621A处理器，你只需要将`Renzheng`上传到你的路由器，赋予执行权限，有点难度了，你要编译程序源代码
