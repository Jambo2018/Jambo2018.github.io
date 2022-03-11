---
title: fastjson反序列化漏洞分析
date: 2021-04-05 13:20:57
tags:
---

fastjson支持AutoType功能，即在序列化的字符串中加入`@type`字段，fastjson就会将数据反序列化为它指定的类型对象。当Server端存在可用的代码执行链时，如`TemplatesImpl`或`JdbcRowSetImpl`，就可以RCE。



## 参考链接

1. [https://xz.aliyun.com/t/8979](https://xz.aliyun.com/t/8979)
2. [https://xz.aliyun.com/t/9052](https://xz.aliyun.com/t/9052)
3. [https://www.freebuf.com/column/180711.html](https://www.freebuf.com/column/180711.html)