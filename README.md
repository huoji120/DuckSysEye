# DuckSysEye
SysEye是一个window上的基于att&ck现代EDR设计思想的威胁响应工具.
不同于EDR,它轻量、高效.自身定位是威胁检出工具.
而不是繁重的、需要付费的、效果不明的所谓的EDR

### 功能特点
1. 基于att&ck设计.所有设计只是为了符合att&ck的攻击路径、攻击链(虽然规则里面没有标注T因为懒惰)
2. 轻量、高效.为了不适用繁重超占内存的ELK设计思路,而且要保证检出的同时保证不会太重,agent端使用了大量规则过滤,这样才使得后端使用sqlite作为数据库成为可能.单机日志平均一天4M.此外轻量级别的客户端一天只占40-400KB的内存.
3. 行为检出,让免杀成为过去式.基于att&ck设计,只看行为不看文件.文件类免杀已经成为过去式.
4. 高扩展性.可随需求定制功能

### 检出截图
.....todo......
[![image](xxx.png)](https://github.com/huoji120/DuckSysEye/raw/main/Image/logo.png)

### 待做列表
1. 更好的前端(目前是VUE-CDN模式,不太好,想换成VUE-CLI)
2. 日志回放
3. 威胁狩猎
4. att&ck热力图
5. 在线规则编辑器
6. 内网横向检测
7. iis、apache、nginx日志搜集分析(aka: XDR)
8. 集成反病毒引擎

### 社区
开源的目的不是为了免费填鸭式教学,或者被免费拿去发公众号引流、去拿去集成产品方案去赚钱,而是要一起完善这个工具,从而实现共赢.
因此成立了一个社区:
https://key08.com
使用反馈、bug反馈等请前往社区
在社区里面拥有工具的改装教程、设计代码、规则交流等.欢迎尝试访问
