---

## This draft is the specific technology

title: 'An RPKI and IPsec-based AS-to-AS Approach for Source Address Validation'
abbrev: RISAV

docname: draft-xu-risav-latest
date: 2022-09-30

# stand_alone: yes

ipr: trust200902
# area: Security Area
wg: Network Working Group
kw: Internet-Draft
cat: info

coding: us-ascii
pi:    # can use array (if all yes) or hash here

toc: yes
sortrefs: yes  # defaults to yes
symrefs: yes

author:
      -
        name: Ke Xu
        org: Tsinghua University
        # abbrev: Tsinghua University
        # street: Qinghuayuan street, Haidian District
        city: Beijing
        # code: 100084
        country: China
        email: xuke@tsinghua.edu.cn
      -
        name: Jianping Wu
        org: Tsinghua University
        # abbrev: Tsinghua University
        # street: Qinghuayuan street, Haidian District
        city: Beijing
        # code: 100084
        country: China
        email: jianping@cernet.edu.cn
      -
        name: Yangfei Guo
        org: Zhongguancun Laboratory
        # abbrev: ZGC Lab
        # street: Cuihu Road, Haidian District
        city: Beijing
        # code: 100095
        country: China
        email: guoyangfei@zgclab.edu.cn
      -
        name: Benjamin M. Schwartz
        org: Google LLC
        #city:
        #country:
        email: bemasc@google.com
      -
        name: Haiyang (Henry) Wang
        org: The University of Minnesota at Duluth
        city: Minnesota
        country: USA
        email: haiyang@d.umn.edu


normative:
  RFC2119:
  RFC2827:
  RFC2986:
  RFC3948:
  RFC4301:
  RFC4302:
  RFC4303:
  RFC5210:
  RFC5635:
  RFC5905:
  RFC5996:
  RFC6278:
  RFC6480:
  RFC7039:
  RFC8174:
  RFC8209:
  RFC8247:
  RFC8704:

informative:
  INTEL:
    title: Achieving 1 Tbps IPsec with AVX-512
    date: April 06, 2021
    target: https://networkbuilders.intel.com/solutionslibrary/3rd-generation-intel-xeon-scalable-processor-achieving-1-tbps-ipsec-with-intel-advanced-vector-extensions-512-technology-guide


# --- note_IESG_Note

--- abstract

This document presents RISAV, a protocol for establishing and using IPsec security between Autonomous Systems (ASes) using the RPKI identity system. In this protocol, the originating AS adds authenticating information to each outgoing packet at its Border Routers (ASBRs), and the receiving AS verifies and strips this information at its ASBRs. Packets that fail validation are dropped by the ASBR. RISAV achieves Source Address Validation among all participating ASes.


--- middle

# Introduction

Source address spoofing has been identified years ago at {{RFC2827}}, and {{RFC5210}} has proposed an Source Address Validation Architecture (SAVA) to alleviate such concerns. SAVA classifies this solution into three layers: Access Network, Intra-AS, and Inter-AS. The Inter-AS concerns the SAV at the AS boundaries. It is more challenging for developing the inter-AS source address validation approach because different ASes run different policies in different ISPs independently. It requires the different ASes to collaborate to verify the source address. The inter-AS SAV is more effective than Access or Intra-AS due to its better cost-effectiveness. However, over years of effort, inter-AS source address validation deployment is still not optimistic. An important reason is the difficulty of balancing the clear security benefits of partial implementations with the scalability of large-scale deployments. uRPF {{RFC5635}} {{RFC8704}}, for example, is a routing-based schemes filter spoofing source address's traffic, which may result in a lack of security benefits due to the dynamic nature of routing or incomplete information caused by partial deployments.

This document provides an RPKI- {{RFC6480}} and IPsec-based {{RFC4301}} inter-AS approach to source address validation (RISAV). RISAV is a cryptography-based SAV mechanism to reduce the spoofing source address. RPKI provides the reflection relationship between AS numbers (ASN) and IP prefixes. IKEv2 is used to negotiate between two ASes with the Security Association (SA) which contains the algorithm, secret key generating material, and IPsec packet type, and so forth. IPsec is designed for secure the Internet at the IP layer. It introduces two protocols, one is AH (authentication header) {{RFC4302}} which provides authenticity of the whole packet, including the source address. The other is ESP (IP Encapsulating Security Payload) {{RFC4303}} which encrypts the whole packet's payload.

## Requirements Language

{::boilerplate bcp14-tagged}


## Terminology

Commonly used terms in this document are described below.

ACS:
: AS Control Server, which is the logical representative of one AS and is responsible for delivering tags and other information to ASBR.

contact IP:
: This IP is the IP address of ACS which is published with the RISAVAnnouncement.

<!--
ASBR:
: AS border router, which is at the boundary of an AS.

SAV:
: Source Address Validation, which verifies the source address of an IP packet and guarantee the source address is valid.
-->

# Overview

The goal of this section is to provides the high level description of what RISAV is and how RISAV works.

## What RISAV Is

RISAV is a cryptographically-based inter-AS source address validation approach that guarantees security benefits at partial deployment. It aims to provide the IP datagram with a valid source address, with the capability of anti-spoofing, anti-replay, light-weight and efficient, and incremental deployment incentives. As a result, RISAV adds a tag to a packet at the source AS Border Router (ASBR) proving that the packet is with a valid source address, and it would verify and remove this tag at the destination ASBR. The tag will be encapsulated in the Integrity Check Value (ICV) field of IPsec AH/ESP.

## How RISAV Works

RISAV uses IKEv2 to negotiate an IPsec security association (SA) between any two ASes. RPKI provides the binding relationship between AS numbers, IP ranges, contact IPs, and public keys. After negotiation, all packets between these ASes are secured by use of a modified AH header or a standard ESP payload.

Before deploying RISAV, each AS sets a contact IP representative. When negotiating or consulting with one AS, the peer MUST first communicate with this contact IP. The AS MUST publish exactly one contact IP for each supported address family (i.e. IPv4 and/or IPv6) in the RPKI database.

A typical workflow of RISAV is shown in {{figure1}}.

~~~~~~~~~~~
                            +--------------+
                            |     IANA     |
                            +--------------+
                                   |--------------------------+
                                   V                          |
                            +--------------+                  |
                            |      RIR     |                  |
                            +--------------+                  |
                           /                \-----------------+-1. Signing CA
                          V                  V                |  Certificate
              +--------------+               +--------------+ |
              |     LIR1     |               |     LIR2     | |
              +--------------+               +--------------+ |
              /                                             \-+
             V                                               V
+--------------+                                           +--------------+
| 3. RISAV     |---------+                          +------| 3. RISAV     |
| Announcement |         | 2. Signing EE Certificate|      | Announcement |
|              | +-------+                          +----+ |              |
|     AS A     | |                                       | |     AS B     |
| contact IP a | V                                       V | contact IP b |
|           #######   --------------------------------  #######           |
|           # ACS #    4. SA Negotiation and Delivery   # ACS #           |
|           #######   --------------------------------  #######           |
|              |                                           |              |
|           ########  +++++++++++++++++++++++++++++++++ ########          |
|           # ASBR #       5. Data Transmission         # ASBR #          |
|           ########         with IPsec AH/ESP          ########          |
|              |      +++++++++++++++++++++++++++++++++    |              |
+--------------+                                           +--------------+
~~~~~~~~~~~
{: #figure1 title="RISAV workflow example."}

1. RPKI process. The five Regional Internet Registry (RIR), authorized by IANA, use their root certificate to sign the Certificate Authority (CA) certificate of the Local Internet Registry (LIR). And after that LIR would use a CA certificate to authorize indirectly the Internet Service Provider (ISP) or directly the Autonomous System (AS). When they obtain their own CA certificate, the AS would sign an End Entity (EE) certificate with a Route Origin Authorisation (ROA) which is a cryptographically signed object that states which AS are authorized to originate a certain prefix. Such the reflection of the ASN relationship with IP prefixes would be broadcast to the network. This is the prerequisite.

2. ACS EE certificate provisioning. The ACS would need its own EE certificate for IKEv2. This EE certificate is REQUIRED like the BGPsec Router Certificate defined in {{RFC8209}}.

3. RISAV announcement. Each participating AS announces its support for RISAV in the RPKI database, including the IP address of its ACS (the "contact IP").

4. SA negotiation and delivery. The ACSes negotiate an SA using IKEv2. When all negotiations are done, the IPsec is established.  After syncrhonization, all ASBRs would get the SA, including the session key and other parameters.

5. IPsec communication. It uses IPsec AH for authentication of the IP source address by default. IPsec is often used in tunnel mode as the IPsec VPN. Here, It expands the gateway to the ASBR. When two ends x and y in AS A and B respectively are communicating, the packet from x arriving at its ASBR RA would use the established IPsec channel for adding the representative tag which is generated with the negotiated and synchronized algorithm, session key, IPsec type, and other items and is filled in the ICV field. After the packet arrives at ASBR RB of AS B, it would be inspected by comparing the consistency of the tag at the packet's ICV field and the tag generated in the same way at the source ASBR.

# Control Plane

The functions of the control plane of RISAV include:

* Announcing that this AS supports RISAV.
* Publishing contact IPs.
* Performing IPsec session initialization (i.e. IKEv2).

These functions are achieved in two steps.  First, each participating AS publishes a Signed Object {{!RFC6488}} in its RPKI Repository containing a `RISAVAnnouncement`:

~~~
RISAVAnnouncement ::= SEQUENCE {
         version [0] INTEGER DEFAULT 0,
         asID ASID,
         contactIP ipAddress }
~~~

When a participating AS discovers another participating AS (via its regular sync of the RPKI database), it initiates an IKEv2 handshake between its own contact IP and the other AS's contact IP.  This handshake MUST include an IKE_AUTH exchange that authenticates both ASes with their RPKI ROA certificates.

Once this handshake is complete, each AS MUST activate RISAV on all outgoing packets, and SHOULD drop all non-RISAV traffic from the other AS after a reasonable grace period (e.g. 60 seconds).

For more information about RPKI, one can refer to {{RFC6480}}.

> OPEN QUESTION: What should we say about cases where the handshake fails?  To be truly secure, all traffic from that AS would have to be dropped...

There may be a number of reasons that cause the handshake or the link fails. When one handshake fails, the ACS would know nothing SAs about the peer AS; vice versa. Arrived packets that should be processed with RISAV would be failed to locate available SAs. Then this packet should be processed like a common packet that not be protected with an IPsec AH/ESP header. So do the source and destination ASBR. When the handshake is complete and running after a while one ACS's link failed, the peer ACS would detect the link is failed with the keepalive packets and remove or deprecate the relative SAs. The keepalive packets is defined in {{RFC3948}} while it is not in NAT traversal. After a grace period, the traffic will be recovered. But the failure should be reported to the administrator with the operations protocols. This would decrease the effect on inter-AS traffic.

## Disabling RISAV

To disable RISAV, a participating AS MUST perform the following steps in order:

1. Stop requiring RISAV authentication of incoming packets.
2. Remove the `RISAVAnnouncement` from the RPKI Repository.
3. Wait at least 24 hours.
4. Stop sending RISAV and shut down the contact IP.

Conversely, if any AS no longer publishes a `RISAVAnnouncement`, other ASes MUST immediately stop sending RISAV to that AS, but MUST NOT delete any negotiated Tunnel Mode SAs for at least 24 hours, in order to continue to process encrypted incoming traffic.

> TODO: Discuss changes to the contact IP, check if there are any race conditions between activation and deactivation, IKEv2 handshakes in progress, SA expiration, etc.

SA has its own expiration time and IKE has its keepalive mechanism. In abnormal case, i.e. the connection is failed after the IKE handshake is established, SA will be always in effect during its lifetime until it expires or the IKE keepalive is failed. In normal case, i.e. the connection is actively down, SA will be expired and RISAV will be disabled immediately.

> OPEN QUESTION: Does IKEv2 have an authenticated permanent rejection option that would help here?



# Data Plane

All the ASBRs of the AS are REQUIRED to enable RISAV. It uses SPI for destination ASBR to locate the SA uniquely when processing the AH header in RISAV.

As defined in {{RFC4301}}, the Security Association Database (SAD) stores all the SAs. One data item in SAD includes an Authentication algorithm and corresponding key when AH is supported. The authentication algorithm could be HMAC-MD5, HMAC-SHA-1, or others.

When a packet arrives at the source ASBR, it will be checked with the destination address by this ASBR first. If the destination address is in the protection range of RISAV, the packet will be checked by the source address next. If the source address belongs to the AS in which the ASBR locates, the packet needs to be modified for RISAV.

The modification that is applied depends on whether IPsec "transport mode" or "tunnel mode" is active.  This is determined by the presence or absence of the USE_TRANSPORT_MODE notification in the IKEv2 handshake.  RISAV implementations MUST support transport mode, and MAY support tunnel mode.

> OPEN QUESTION: How do peers express a preference or requirement for transport or tunnel mode?



When a packet arrives at the destination ASBR, it will check the destination address and the source address. If the destination belongs to the AS that the destination ASBR locates in and the source address is in an AS with which this AS has a RISAV SA, the packet is subject to RISAV processing.

To avoid DoS attacks, participating ASes MUST drop any outgoing packet to the contact IP of another AS.  Only the AS operator's systems (i.e. the ACS and ASBRs) are permitted to send packets to the contact IPs of other ASes.  ASBRs MAY drop inbound packets to the contact IP from non-participating ASes.

## Transport Mode

To avoid conflict with other uses of IPsec, RISAV defines its own variant of the IPsec Authentication Header (AH).  The RISAV-AH header format is shown in {{fig2}}.

~~~~~~~~~~~
                     1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Header   |  Payload Len  |           RESERVED            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Security Parameters Index (SPI)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Integrity Check Value (ICV)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~~
{: #fig2 title="RISAV-AH Format."}

This format is identical to IPsec standard AH except that the Sequence Number is omitted, because RISAV is presumed to be a "multi-sender SA" for which anti-replay defense is not supported {{RFC4302, Section 2.5}}.  This change saves 8 octets when the ICV is 16, 24, or 32 octets.  For a 16-octet ICV (most common), RISAV-AH adds 24 octets to each packet.

The RISAV-AH header is only for AS-to-AS communication.  ASes MUST strip off all RISAV-AH headers for packets whose destination is inside the AS, even if the AS is not currently inspecting the ICV values.

In transport mode, each AS's SA Database (SAD) is indexed by SPI and counterpart AS, regardless of the source and destination IPs.

## Tunnel Mode

In tunnel mode, a RISAV sender ASBR wraps each outgoing packet in an ESP payload.  Each ASBR uses its own source address, and sets the destination address to the contact IP of the destination AS.

The contact IP decrypts all IPsec traffic to recover the original packets, which are forwarded to the correct destination.  After decryption, the receiving AS MUST check that the source IP and destination IP are in the same AS as the outer source and destination, respectively.

In Tunnel mode, each ASBR maintains its own copy of the SA Database (SAD).  The SAD is indexed by SPI and counterpart AS, except for the replay defense window, which is additionally scoped to the source IP. If a valid ESP packet is received from an unknown IP address, the receiving AS SHOULD allocate a new replay defense window, subject to resource constraints.  This allows replay defense to work as usual.  (If the contact IP is implemented as an ECMP cluster, effective replay defense may require consistent hashing.)

Tunnel mode imposes a space overhead of 73 octets in IPv6.

> PROBLEM: ESP doesn't protect the source IP, so a packet could be replayed by changing the source IP.  Can we negotiate an extension to ESP that covers the IP header?  Or could we always send from the contact IP and encode the ASBR ID in the low bits of the SPI?

> OPEN QUESTION: Do we need multiple contact IPs per AS, to support fragmented ASes?

# Possible Extensions

This section presents potential additions to the design.

> TODO: Remove this section once we have consensus on whether these extensions are worthwhile.

## Header-only authentication

Original IPsec AH needs to authenticate the whole constant part of a packet so that it needs to spend amounts of time finding and processing unchangeable fields in the packet. However, RISAV only needs to find a few changeless fields to authenticate the packet decreasing the cost dramatically.

As authenticating the whole packet causes a heavy burden in the computation, we could define an IKE parameter to negotiate a header-only variant of transport mode that only authenticates the IP source address, IP destination address, etc.

This would likely result in a 10-30x decrease in cryptographic cost compared to standard IPsec.  However, it would also offer no SAV defense against any attacker who can view legitimate traffic.  An attacker who can read a single authenticated packet could simply replace the payload, allowing it to issue an unlimited number of spoofed packets.

## Time-based key rotation

It has two ways for an ACS to generate tags. One is using a state machine. The state machine runs and triggers the state transition when time is up. The tag is generated in the process of state transition as the side product. The two ACS in peer AS respectively before data transmission will maintain one state machine pair for each bound. The state machine runs simultaneously after the initial state, state transition algorithm, and state transition interval are negotiated, thus they generate the same tag at the same time. Time triggers state transition which means the ACS MUST synchronize the time to the same time base using like NTP defined in {{RFC5905}}.

For the tag generation method, it MUST be to specify the initial state and initial state length of the state machine, the identifier of a state machine, state transition interval, length of generated Tag, and Tag. For the SA, they will transfer all these payloads in a secure channel between ACS and ASBRs, for instance, in ESP {{RFC4303}}. It is RECOMMENDED to transfer the tags rather than the SA for security and efficiency considerations. The initial state and its length can be specified at the Key Exchange Payload with nothing to be changed. The state machine identifier is the SPI value as the SPI value is uniquely in RISAV. The state transition interval and length of generated Tag should be negotiated by the pair ACS, which will need to allocate one SA attribute. The generated Tag will be sent from ACS to ASBR in a secure channel which MAY be, for example, ESP {{RFC4303}}.

## Static Negotiation

The use of IKEv2 between ASes might be fragile, and creates a number of potential race conditions (e.g. if the RPKI database contents change during the handshake).  It is also potentially costly to implement, requiring O(N^2) network activity for N participating ASes.  If these challenges prove significant, one alternative would be to perform the handshake statically via the RPKI database.  For example, static-static ECDH {{RFC6278}} would allow ASes to agree on shared secrets simply by syncing the RPKI database.

Static negotiation makes endpoints nearly stateless, which simplifies the provisioning of ASBRs.  However, it requires inventing a novel IPsec negotiation system, so it seems best to try a design using IKEv2 first.

# Security Consideration

## Incremental benefit from partial deployment

RISAV provides significant security benefits even if it is only deployed by a fraction of all ASes.  This is particularly clear in the context of reflection attacks.  If two networks implement RISAV, no one in any other network can trigger a reflection attack between these two networks.  Thus, if X% of ASes (selected at random) implement RISAV, participating ASes should see an X% reduction in reflection attack traffic volume.

## Threat models for SAV

Different RISAV modes potentially offer different security properties.  For example, in Transport Mode, off-path attackers cannot spoof the source IPs of a participating AS, but any attacker with access to valid traffic can replay it (from anywhere), potentially enabling DoS attacks by replaying expensive traffic (e.g. TCP SYNs, QUIC Initials).  ASes that wish to have replay defense, and are willing to pay the extra data-plane costs, should prefer tunnel mode.

## Multipath Problem {#MPProblem}

This is the problem that requires one AS should be logically presented as one entity. That means all ASBRs of one AS should be acted like one ASBR. Otherwise, different source ASBR would add different IPsec ICV value to the packet. After forwarding, the packet may not arrive at the ASBR as the source ASBR thought. The ICV check may be failed. So the ACS is the entity that represents the AS to negotiate and communicate with peers. The ACS would deliver the messages including SAs and generate tags to the ASBR so that all ASBRs in the same AS would work like one ASBR for they have the same processing material and process in the same way. Thus, the multipath problem is solved.

## Compatibility

### With end-to-end IPsec

When RISAV is used in transport mode, there is a risk of confusion between the RISAV AH header and end-to-end AH headers used by applications.  This risk is particularly clear during transition periods, when the recipient is not sure whether the sender is using RISAV or not.

To avoid any such confusion, RISAV's transport mode uses a specialized RISAV-AH header.  (In tunnel mode, no such confusion is possible.)

### With other SAV mechanisms

RISAV can OPTIONAL cooperate with intra-domain SAV and access-layer SAV, such as {{RFC8704}} or SAVI {{RFC7039}}. Only when intra-domain or access-layer SAV, if deployed, check passed can the packet process and forward correctly.

# Operational Considerations

## Reliability

The ACS, represented by a contact IP, must be a high-availability, high-performance service to avoid outages.  When it chooses to use a logical ACS, one AS will elect one distinguished ASBR as the ACS. The distinguished ASBR acting as an ACS will represent the whole AS to communicate with peer AS's ACS. This election takes place prior to the IKE negotiation. An ASBR MUST be a BGP speaker before it is elected as the distinguished ASBR.

## Performance

RISAV requires participating ASes to perform symmetric cryptography on every RISAV-protected packet that they originate or terminate.  This will require significant additional compute capacity that may not be present on existing networks.  However, until most ASes actually implement RISAV, the implementation cost for the few that do is greatly reduced.  For example, if 5% of networks implement RISAV, then participating networks will only need to apply RISAV to 5% of their traffic.

Thanks to broad interest in optimization of IPsec, very high performance implementations are already available.  For example, as of 2021 an IPsec throughput of 1 Terabit per second was achievable using optimized software on a single server {{INTEL}}.

## MTU

> TODO: Figure out what to say about MTU, PMTUD, etc.  Perhaps an MTU probe is required after setup?  Or on an ongoing basis?

## NAT scenario

As all the outter IP header should be the unicast IP address, NAT-traversal mode is not necesarry in inter-AS SAV.

# IANA Consideration

IF APPROVED IANA is requested to add the following entry to the Assigned Internet Protocol Numbers registry:

* Decimal: $TBD
* Keyword: RISAV-AH
* Protocol: AS-to-AS Authentication Header
* IPv6 Extension Header: Y
* Refrence: (This document)

<!-- # Acknowledgements -->
<!-- TBD. -->

--- back
