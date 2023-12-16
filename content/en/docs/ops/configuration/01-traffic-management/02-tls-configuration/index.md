---
title: Understanding TLS Configuration
linktitle: TLS Configuration
description: How to configure TLS settings to secure network traffic.
weight: 30
keywords: [traffic-management,proxy]
owner: istio/wg-networking-maintainers
test: n/a
---

One of Istio's most important features is the ability to lock down and secure network traffic to, from,
and within the mesh. However, configuring TLS settings can be confusing and a common source of misconfiguration.
This document attempts to explain the various connections involved when sending requests in Istio and how
their associated TLS settings are configured.
Refer to [TLS configuration mistakes](/docs/ops/common-problems/network-issues/#tls-configuration-mistakes)
for a summary of some the most common TLS configuration problems.
Istio 最重要的功能之一是能够锁定和保护进出网格以及网格内的网络流量。
然而，配置 TLS 设置可能会令人困惑，并且是错误配置的常见原因。
本文档试图解释在 Istio 中发送请求时涉及的各种连接以及如何配置其关联的 TLS 设置。
请参阅 TLS 配置错误，了解一些最常见的 TLS 配置问题的摘要。

## Sidecars

Sidecar traffic has a variety of associated connections. Let's break them down one at a time.
Sidecar 流量有多种关联连接。 让我们一次一个地分解它们。

{{< image width="100%"
    link="sidecar-connections.svg"
    alt="Sidecar proxy network connections"
    title="Sidecar connections"
    caption="Sidecar proxy network connections"
    >}}

1. **External inbound traffic**
    This is traffic coming from an outside client that is captured by the sidecar.
    If the client is inside the mesh, this traffic may be encrypted with Istio mutual TLS.
    By default, the sidecar will be configured to accept both mTLS and non-mTLS traffic, known as `PERMISSIVE` mode.
    The mode can alternatively be configured to `STRICT`, where traffic must be mTLS, or `DISABLE`, where traffic must be plaintext.
    The mTLS mode is configured using a [`PeerAuthentication` resource](/docs/reference/config/security/peer_authentication/).
    这是来自 sidecar 捕获的外部客户端的流量。
    如果客户端位于网格内部，则可以使用 Istio 双向 TLS 对该流量进行加密。
    默认情况下，sidecar 将配置为接受 mTLS 和非 mTLS 流量，称为 PERMISSIVE 模式。
    该模式也可以配置为 STRICT（其中流量必须为 mTLS）或 DISABLE（其中流量必须为纯文本）。
    mTLS 模式是使用 PeerAuthentication 资源配置的。

1. **Local inbound traffic**
    This is traffic going to your application service, from the sidecar. This traffic will always be forwarded as-is.
    Note that this does not mean it's always plaintext; the sidecar may pass a TLS connection through.
    It just means that a new TLS connection will never be originated from the sidecar.
    这是从 sidecar 流向您的应用程序服务的流量。 此流量将始终按原样转发。
    请注意，这并不意味着它始终是明文； sidecar 可以传递 TLS 连接。
    这只是意味着新的 TLS 连接永远不会从 sidecar 发起。

1. **Local outbound traffic**
    This is outgoing traffic from your application service that is intercepted by the sidecar.
    Your application may be sending plaintext or TLS traffic.
    If [automatic protocol selection](/docs/ops/configuration/traffic-management/protocol-selection/#automatic-protocol-selection)
    is enabled, Istio will automatically detect the protocol. Otherwise you should use the port name in the destination service to
    [manually specify the protocol](/docs/ops/configuration/traffic-management/protocol-selection/#explicit-protocol-selection).
    这是由 sidecar 拦截的来自应用程序服务的出站流量。
    您的应用程序可能正在发送明文或 TLS 流量。
    如果启用自动协议选择，Istio 将自动检测协议。
    否则，您应该使用目标服务中的端口名称来手动指定协议。

1. **External outbound traffic**
    This is traffic leaving the sidecar to some external destination. Traffic can be forwarded as is, or a TLS connection can
    be initiated (mTLS or standard TLS). This is controlled using the TLS mode setting in the `trafficPolicy` of a
    [`DestinationRule` resource](/docs/reference/config/networking/destination-rule/).
    A mode setting of `DISABLE` will send plaintext, while `SIMPLE`, `MUTUAL`, and `ISTIO_MUTUAL` will originate a TLS connection.
    这是离开 sidecar 到某个外部目的地的流量。
    流量可以按原样转发，也可以启动 TLS 连接（mTLS 或标准 TLS）。
    这是使用 DestinationRule 资源的 TrafficPolicy 中的 TLS 模式设置进行控制的。
    DISABLE 模式设置将发送明文，而 SIMPLE、MUTUAL 和 ISTIO_MUTUAL 将发起 TLS 连接。

The key takeaways are:

- `PeerAuthentication` is used to configure what type of mTLS traffic the sidecar will accept.
  PeerAuthentication 用于配置 sidecar 将接受的 mTLS 流量类型。

- `DestinationRule` is used to configure what type of TLS traffic the sidecar will send.
  DestinationRule 用于配置 sidecar 将发送的 TLS 流量类型。

- Port names, or automatic protocol selection, determines which protocol the sidecar will parse traffic as.
  端口名称或自动协议选择决定了 sidecar 将解析流量的协议。

## Auto mTLS

As described above, a `DestinationRule` controls whether outgoing traffic uses mTLS or not.
However, configuring this for every workload can be tedious. Typically, you want Istio to always use mTLS
wherever possible, and only send plaintext to workloads that are not part of the mesh (i.e., ones without sidecars).
如上所述，DestinationRule 控制传出流量是否使用 mTLS。
然而，为每个工作负载进行配置可能会很乏味。
通常，您希望 Istio 始终尽可能使用 mTLS，并且仅将明文发送到不属于网格的工作负载（即没有 sidecar 的工作负载）。

Istio makes this easy with a feature called "Auto mTLS". Auto mTLS works by doing exactly that. If TLS settings are
not explicitly configured in a `DestinationRule`, the sidecar will automatically determine if
[Istio mutual TLS](/about/faq/#difference-between-mutual-and-istio-mutual) should be sent.
This means that without any configuration, all inter-mesh traffic will be mTLS encrypted.
Istio 通过“Auto mTLS”功能使这一切变得简单。 Auto mTLS 的工作原理正是如此。
如果未在 DestinationRule 中显式配置 TLS 设置，则 sidecar 将自动确定是否应发送 Istio 双向 TLS。
这意味着无需任何配置，所有网格间流量都将进行 mTLS 加密。

## Gateways

Any given request to a gateway will have two connections.
对网关的任何给定请求都将有两个连接。

{{< image width="100%"
    link="gateway-connections.svg"
    alt="Gateway network connections"
    title="Gateway connections"
    caption="Gateway network connections"
    >}}

1. The inbound request, initiated by some client such as `curl` or a web browser. This is often called the "downstream" connection.
   入站请求，由某些客户端（例如curl或Web浏览器）发起。 这通常称为“下游”连接。

2. The outbound request, initiated by the gateway to some backend. This is often called the "upstream" connection.
   出站请求，由网关向某个后端发起。 这通常称为“上游”连接。

Both of these connections have independent TLS configurations.
这两个连接都有独立的 TLS 配置。

Note that the configuration of ingress and egress gateways are identical.
The `istio-ingress-gateway` and `istio-egress-gateway` are just two specialized gateway deployments.
The difference is that the client of an ingress gateway is running outside of the mesh while in the case of an egress gateway,
the destination is outside of the mesh.
请注意，入口和出口网关的配置是相同的。 istio-ingress-gateway 和 istio-egress-gateway 只是两个专门的网关部署。
不同之处在于入口网关的客户端在网格之外运行，而在出口网关的情况下，目的地在网格之外。

### Inbound

As part of the inbound request, the gateway must decode the traffic in order to apply routing rules.
This is done based on the server configuration in a [`Gateway` resource](/docs/reference/config/networking/gateway/).
For example, if an inbound connection is plaintext HTTP, the port protocol is configured as `HTTP`:
作为入站请求的一部分，网关必须对流量进行解码才能应用路由规则。
这是根据网关资源中的服务器配置完成的。
例如，如果入站连接是纯文本 HTTP，则端口协议配置为 HTTP：

{{< text yaml >}}
apiVersion: networking.istio.io/v1beta1
kind: Gateway
...
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
{{< /text >}}

Similarly, for raw TCP traffic, the protocol would be set to `TCP`.
同样，对于原始 TCP 流量，协议将设置为 TCP。

For TLS connections, there are a few more options:
对于 TLS 连接，还有更多选项：

1. What protocol is encapsulated?
    If the connection is HTTPS, the server protocol should be configured as `HTTPS`.
    Otherwise, for a raw TCP connection encapsulated with TLS, the protocol should be set to `TLS`.
    封装了什么协议？ 如果连接是HTTPS，则服务器协议应配置为HTTPS。 否则，对于使用 TLS 封装的原始 TCP 连接，协议应设置为 TLS。

1. Is the TLS connection terminated or passed through?
    For passthrough traffic, configure the TLS mode field to `PASSTHROUGH`:
    TLS 连接是终止还是通过？ 对于直通流量，将 TLS 模式字段配置为 PASSTHROUGH：

    {{< text yaml >}}
    apiVersion: networking.istio.io/v1beta1
    kind: Gateway
    ...
      servers:
      - port:
          number: 443
          name: https
          protocol: HTTPS
        tls:
          mode: PASSTHROUGH
    {{< /text >}}

    In this mode, Istio will route based on SNI information and forward the connection as-is to the destination.
    在此模式下，Istio 将根据 SNI 信息进行路由，并将连接按原样转发到目的地。

1. Should mutual TLS be used?
    Mutual TLS can be configured through the TLS mode `MUTUAL`. When this is configured, a client certificate will be
    requested and verified against the configured `caCertificates` or `credentialName`:
    是否应该使用双向 TLS？ 可以通过 TLS 模式 MUTUAL 配置相互 TLS。
    配置此选项后，将请求客户端证书并根据配置的 caCertificates 或 credentialName 进行验证：

    {{< text yaml >}}
    apiVersion: networking.istio.io/v1beta1
    kind: Gateway
    ...
      servers:
      - port:
          number: 443
          name: https
          protocol: HTTPS
        tls:
          mode: MUTUAL
          caCertificates: ...
    {{< /text >}}

### Outbound

While the inbound side configures what type of traffic to expect and how to process it, the outbound configuration controls
what type of traffic the gateway will send. This is configured by the TLS settings in a `DestinationRule`,
just like external outbound traffic from [sidecars](#sidecars), or [auto mTLS](#auto-mtls) by default.
入站端配置预期的流量类型以及如何处理该流量，而出站配置控制网关将发送的流量类型。
这是通过 DestinationRule 中的 TLS 设置进行配置的，就像来自 sidecar 的外部出站流量或默认情况下的自动 mTLS 一样。

The only difference is that you should be careful to consider the `Gateway` settings when configuring this.
For example, if the `Gateway` is configured with TLS `PASSTHROUGH` while the `DestinationRule` configures TLS origination,
you will end up with [double encryption](/docs/ops/common-problems/network-issues/#double-tls).
This works, but is often not the desired behavior.
唯一的区别是您在配置此选项时应小心考虑网关设置。
例如，如果网关配置为 TLS PASSTHROUGH，而 DestinationRule 配置 TLS 发起，则最终将获得双重加密。 这可行，但通常不是所需的行为。

A `VirtualService` bound to the gateway needs care as well to
[ensure it is consistent](/docs/ops/common-problems/network-issues/#gateway-mismatch)
with the `Gateway` definition.
绑定到网关的 VirtualService 也需要小心，以确保它与网关定义一致。
