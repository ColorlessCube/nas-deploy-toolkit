# NAS 部署专用 WireGuard

采用 `wgdeploy` 独立接口和 `10.44.10.0/24`，路由器为 `10.44.10.1`，监听 IPv4 UDP `51821`。每个仓库注册独立 peer `/32`，如 ASS 为 `10.44.10.2/32`；客户端只路由 NAS `192.168.100.2/32`。不要复用既有 `wgsite` 的密钥，也不要在不同仓库复用部署 peer。

通过现有管理员连接应用配置，先备份 `/etc/config/network`、`/etc/config/firewall` 并确认无未提交 UCI 变更。密钥在路由器本地生成，网络配置权限为 `0600`。接口加入单独的 `deploy` 区域，`input REJECT`、`forward REJECT`、`output ACCEPT`；没有到 LAN/WAN 的区域级 forwarding。仅添加每个 peer 到 NAS TCP 22 的精确规则和 WAN UDP 51821 的入口规则。

新增仓库时追加 peer 和该 `/32` 的 NAS SSH 规则。接口和区域只建立一次；不要重建现有两地 VPN。管理操作使用 UCI 的命名段，例如：

```uci
config interface 'wgdeploy'
    option proto 'wireguard'
    option private_key '<router-private-key>'
    option listen_port '51821'
    option mtu '1420'
    list addresses '10.44.10.1/24'

config wireguard_wgdeploy 'deploy_ass'
    option public_key '<repository-public-key>'
    option route_allowed_ips '1'
    list allowed_ips '10.44.10.2/32'

config zone 'deploy'
    option name 'deploy'
    list network 'wgdeploy'
    option input 'REJECT'
    option output 'ACCEPT'
    option forward 'REJECT'

config rule 'deploy_wireguard'
    option name 'Deploy-WireGuard'
    option src 'wan'
    option family 'ipv4'
    option proto 'udp'
    option dest_port '51821'
    option target 'ACCEPT'

config rule 'deploy_ass_ssh'
    option name 'Deploy-ASS-SSH'
    option src 'deploy'
    option dest 'lan'
    option src_ip '10.44.10.2'
    option dest_ip '192.168.100.2'
    option family 'ipv4'
    option proto 'tcp'
    option dest_port '22'
    option target 'ACCEPT'
```

在所有精确 SSH 放行之后增加以下规则，确保其他请求在部署区域链内结束，不继续进入全局 UPnP 等规则：

```uci
config rule 'deploy_deny_forward'
    option name 'Deploy-Deny-Other-Forward'
    option src 'deploy'
    option dest '*'
    option proto 'all'
    option target 'REJECT'
```

验证 `fw4 check` 后，仅 `ifup wgdeploy` 并重载防火墙；核对接口归属、精确允许和拒绝计数器，重新确认 `wgsite` 握手。撤销仓库时先删对应 GitHub Secret、NAS 授权 key，再删该 peer 和放行规则，保留其他仓库与原有 VPN。
