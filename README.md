# rootkit
国科大软件安全原理作业

在 Ubuntu 20.04 Linux 5.4.0-52 测试通过

## 使用

编译：

```bash
make
```

插入模块：

```bash
make insmod
```

删除模块：

```bash
make rmmod
```

## 后门指令

该 rootkit hook 了 openat 指令作为后门指令，可以直接使用 `cat '!!xxxx'` 进行使用

+ 隐藏文件
  + cat '!!hide_file filename'
  + cat '!!unhide_file filename'
  + 例如 `cat '!!hide_file /home/plusls/114514'`
+ 隐藏进程
  + cat '!!hide_pid pid_num'
  + cat '!!unhide_pid pid_num'
  + 例如 `cat '!!hide_pid 114514'`
+ 隐藏端口
  + cat '!!hide_port protocol port_num'
  + cat '!!unhide_port protocol port_num'
  + 例如 `cat '!!unhide_port tcp6 1234'`
+ 获取特权
  + cat '!!get_root_shell'

## 已知问题

+ 由于通过脱链表实现隐藏进程，可能会导致内核崩溃
+ 访问全局变量未加锁，可能并发会存在问题
+ recvmsg 系统调用 hook 可能存在越界访问漏洞（没仔细审）
+ 源码中有隐藏自身模块的函数，由于目前未找到恢复模块的方式，因此未实装
+ 隐藏的文件被删除后恢复隐藏可能会出现问题
+ 针对 ss 指令隐藏端口目前不支持根据协议进行隐藏，隐藏 tcp:11451 会导致 udp:11451 也被隐藏
+ hook sys_bind 实现了防止 bind 扫描隐藏端口，但是同样未区分协议
+ 未实现 x86-32 syscall_hook

## 参考资料

+ Hook recvmsg：https://github.com/nnedkov/swiss_army_rootkit/blob/master/Assignment_6/socket_masker.c
+ ss 源码：https://github.com/CumulusNetworks/iproute2/blob/master/misc/ss.c
+ LibZeroEvil：https://github.com/NoviceLive/research-rootkit
+ Linux 源码：https://github.com/torvalds/linux

## 感谢

Rootkit 的大部分功能是由别的大佬实现的

感谢大佬

+ ZoEplA：https://github.com/ZoEplA
+ shijy16：https://github.com/shijy16