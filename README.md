# Gbdt-SDK
云易Gbdt-SDKv1.3
持续更新中...
Gbdt-SDKv1.3更新日志：
* 兼容http协议和WebSocket双通道传输协议，优化并集成了sdk的框架加密算法和WebSocket连接器。
* 注意事项：
* 1.WebSocket心跳请勿高频并发亦或者高频请求，否则将会拒绝响应
* 2.WebSocket需要心跳维持连接超时10s未发送任何请求将主动断开连接
* 3.由于这次更新的加密算法框架所以sdk将不支持v1.3之前的版本
