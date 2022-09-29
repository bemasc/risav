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
  RFC4301:
  RFC4302:
  RFC4303:
  RFC5210:
  RFC5635:
  RFC5905:
  RFC5996:
  RFC6480:
  RFC7039:
  RFC8174:
  RFC8209:
  RFC8704:

informative:

# --- note_IESG_Note

--- abstract

This document identifies a need for static-static ECDH, RPKI, and IPsec based AS-to-AS approach for detection and mitigation of inter-AS source address validation (RISAV). The RISAV aims to reusing existing protocols to provide a light-weight packet's tag and with the incremental deployability to significantly reduce the spoofed source address in the Internet.


--- middle

# Introduction

Source address spoofing has been identified years ago at {{RFC2827}}, and {{RFC5210}} has proposed an Source Address Validation Architecture (SAVA) to alleviate such concerns. SAVA classifies this solution into three layers: Access Network, Intra-AS, and Inter-AS. The Inter-AS concerns the SAV at the AS boundaries. It is more challenging for developing the inter-AS source address validation approach because different ASes run different policies in different ISPs independently. It requires the different ASes to collaborate to verify the source address. The inter-AS SAV is more effective than Access or Intra-AS due to its better cost-effectiveness. However, over years of effort, inter-AS source address validation deployment is still not optimistic. An important reason is the difficulty of balancing the clear security benefits of partial implementations with the scalability of large-scale deployments. uRPF {{RFC5635}} {{RFC8704}}, for example, is a routing-based schemes filter spoofing source address's traffic, which may result in a lack of security benefits due to the dynamic nature of routing or incomplete information caused by partial deployments.

This document provides a static-static ECDH, RPKI and IPsec-based {{RFC4301}} inter-AS approach to source address validation (RISAV). RISAV is a cryptography-based SAV mechanism to reduce the spoofing source address. It combines static-static ECDH (Elliptic Curve Diffie–Hellman key Exchange), RPKI (Resource Public Key Infrastructure), and IPsec (IP Security). RPKI provides the reflection relationship between AS numbers (ASN) and IP prefixes. ECDH negotiates between two ASes with the Security Association (SA) which contains the algorithm, secret key generating material, and IPsec packet type, and so forth. IPsec is designed for secure the Internet at the IP layer. It introduces two protocols, one is AH (authentication header) {{RFC4302}} which provides authenticity of the whole packet, including the source address. The other is ESP (IP Encapsulating Security Payload) {{RFC4303}} which encrypts the whole packet's payload.

## Requirements Language

{::boilerplate bcp14-tagged}

<!--
# Terminology

Commonly used terms in this document are described below.

ACS:
: AS Control Server, which is the logical representative of one AS and is responsible for delivering tags and other information to ASBR.

ASBR:
: AS border router, which is at the boundary of an AS.

Tag:
: The bit-string that authenticates identification of source address of a packet.

SAV:
: Source Address Validation, which verifies the source address of an IP packet and guarantee the source address is valid.

Signature:
: The final bit-string is placed at the AH's field, which is different for each packet.
-->

# Overview

The goal of this section is to provides the high level description of how RISAV works. RISAV is a cryptography-b  ased inter-AS source address validation method that guarantees security benefits at partial deployment. RISAV uses static-static ECDH
<!--
RPKI to obtain the binding relationship between AS numbers and IP prefixes. It uses IKE to negotiate the IKE SA and IPsec SA for generating the tag presenting the integrity of the IP source address. And the IPsec Authentication Header (AH) would be used to carry the tag in communication.
-->
1. RPKI process. The five Reginal Internet Registry (RIR) would be authorized by IANA. They use their root certificate to sign the Certificate Authority (CA) certificate of the Local Internet Registry (LIR). And after that LIR would use a CA certificate to authorize indirectly the Internet Service Provider (ISP) or directly the Autonomous System (AS). When they obtain their own CA certificate, the AS would sign an End Entity (EE) certificate with a Route Origin Authorisation (ROA) which is a cryptographically signed object that states which AS are authorized to originate a certain prefix. Such the reflection of ASN relationship with IP prefixes would be broadcast to the network.

2. Sign ASBR EE certificate. This EE certificate is just like the BGPsec Router Certificate defined in {{RFC8209}}. The ASBR would need its own EE certificate for and only for generating and verifying the signature in the AH header directly or indirectly.

3. IKE process. Before IPsec establishing, the SA must be reached an agreement. There are two ways to negotiate the SA. One is mutual config all the parameters and the other one is using IKE for dynamic negotiating these parameters. Currently used is IKE version 2 (IKEv2, for short using IKE below). Typically, IKE would produce IKE SA in the IKE_SA_INIT exchange and IPsec SA in the IKE_AUTH exchange. This will be done in an ACS.

4. SA or tag delivery. When all negotiations are done, the IPsec is established. If the ACS is an ASBR actually, it would deliver SA to the other ASBR in this AS. Otherwise, it would deliver the tags generated by the state machine. This delivery will be processed in a secure channel just like using IPsec ESP.

5. IPsec AH communication. It uses IPsec AH for authentication of the IP source address.  IPsec is often used in tunnel mode as the IPsec VPN. Here, It expands the gateway to the AS border router (ASBR). When two ends x and y in AS X and Y respectively are communicating, the packet from x arriving at its ASBR RA would use the established IPsec channel for adding the representative tag. After the packet arrives at ASBR RB of AS Y, it would be inspected by comparing the consistency of the tag. The tag will be encapsulated in the ICV field in AH.

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
                           /                \-----------------+-1. signed CA
                          V                  V                |  certificate
              +--------------+               +--------------+ |
              |     LIR1     |               |     LIR2     | |
              +--------------+               +--------------+ |
              /                                             \-+
             V   +------ 2. signed EE certificate -------+   V
+--------------+ |                                       | +--------------+
|              | |    --------------------------------   | |              |
|              | |          3. IKE negotiation           | |              |
|     AS A     | |    --------------------------------   | |     AS B     |
|              | V                                       V |              |
|           ########  --------------------------------  ########          |
|           # ASBR #           4. SA Deliver            # ASBR #          |
|           ########  --------------------------------  ########          |
|              |                                           |   Prefix Y   |
|   Prefix X   |      +++++++++++++++++++++++++++++++++    | Public Key B |
| Public Key A |           5. data transmission            |              |
|              |              using IPsec AH               |              |
|              |      +++++++++++++++++++++++++++++++++    |              |
+--------------+                                           +--------------+
~~~~~~~~~~~
{: #figure1 title="RISAV workflow example."}

# Control Plane

The functions of the control plane of RISAV include ASN-Prefix relationship announcement, Tag management, and ASN-Tag relationship announcement.

## ASN-Prefix relationship announcement

RISAV uses RPKI to manage the relationship between ASN and IP prefixes. So when one AS wants to deploy RISAV, it should implement RPKI first. When RPKI is deployed, the validated ROA cache SHOULD be sent to the ASBR for routing and forwarding packets.

The ROA whose status is valid can be used with IPsec to prevent source address spoofing. That means only the prefix contained in valid ROA would valuably and correctly be protected.

For more information about RPKI, one can refer to {{RFC6480}}.

## Tag management

Before introducing the ASN-Tag relationship announcement, it shall be described what is a tag and how it is generated.

A tag is a variable bit-string that is generated at an entity in AS. This entity is AS Control Server (ACS). The tag is used with the authentication algorithm to generate the signature. That means the tag is the key to the authentication. When communicating, the tag would not be directly tagged to the IPsec AH of the packet, replacing it with a signature instead, which will be different with different packets. One AS SHOULD have at most two tags in effect in the same bound simultaneously for Key-Rover.

It has two ways for an ACS to generate tags. One is using a state machine. The state machine runs and triggers the state transition when time is up. The tag is generated in the process of state transition as the side product. The two ACS in peer AS respectively before data transmission will maintain one state machine pair for each bound. The state machine runs simultaneously after the initial state, state transition algorithm, and state transition interval are negotiated, thus they generate the same tag at the same time. Time triggers state transition which means the ACS MUST synchronize the time to the same time base using like NTP defined in {{RFC5905}}.

The other way to generate a tag is by applying the original SA. The IPsec channel is established when the IKE_AUTH process is finished. SA includes the specified AH, the authentication algorithm, the key used for authentication, etc. So two IKE entities have negotiated SA. All ASBR in one AS SHOULD use the same SA.

When it chooses to use a logical ACS, one AS will elect one distinguished ASBR as the ACS. The distinguished ASBR acting as an ACS will represent the whole AS to communicate with peer AS's ACS. This election takes place prior to the IKE negotiation. An ASBR MUST be a BGP speaker before it is elected as the distinguished ASBR. This is an OPTIONAL operation to use this logical ACS.

## ASN-Tag relationship announcement

Corresponding to the tag generating, it also has two ways to announce the ASN-Tag binding relationship. The first is to deliver the generated tags and the second is to deliver the original SA.

Thus, there must be a header format definition to transfer these tags and SA. In RISAV, it uses the header and payload formats defined in {{RFC5996}}. Meanwhile, there are some almost negligible changes to the formats. For the tag generation method, it MUST be to specify the initial state and initial state length of the state machine, the identifier of a state machine, state transition interval, length of generated Tag, and Tag. For the SA, they will transfer all these payloads in a secure channel between ACS and ASBRs, for instance, in ESP {{RFC4303}}. It is RECOMMENDED to transfer the tags rather than the SA for security and efficiency considerations. The initial state and its length can be specified at the Key Exchange Payload with nothing to be changed. The state machine identifier is the SPI value as the SPI value is uniquely in RISAV. The state transition interval and length of generated Tag should be negotiated by the pair ACS, which will need to allocate one SA attribute. The generated Tag will be sent from ACS to ASBR in a secure channel which MAY be, for example, ESP {{RFC4303}}.

# Data Plane

The functions of the data plane of RISAV include source address checking and tag processing.

RISAV redesign the original AH format as shown in {{fig2}}.

~~~~~~~~~~~
                     1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Header   |  Payload Len  |          RESERVED             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Security Parameters Index (SPI)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Sequence Number Field                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Prefix Length |  SIG Length   |           RESERVED            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Signature - SIG (variable)                 |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~~
{: #fig2 title="RISAV AH Format."}

Prefix Length:
: The prefix length in valid ROA matched the IP source address. It presents the valid length of the IP source address prefix.

SIG Length:
: The length of the variable signature. It is the octets in Signature.

Signature:
: The result of the authentication algorithm with the key.

All the ASBRs of the AS are REQUIRED to enable RISAV. And RISAV can OPTIONAL cooperate with intra-domain SAV and access-layer SAV, such as {{RFC8704}} or SAVI {{RFC7039}}. Only when intra-domain or access-layer SAV, if deployed, check passed can the packet process and forward correctly. It uses SPI for destination ASBR to locate the SA uniquely when processing the AH header in RISAV.

As defined in {{RFC4301}}, the Security Association Database (SAD) stores all the SAs. One data item in SAD includes an Authentication algorithm and corresponding key when AH is supported. The authentication algorithm could be HMAC-MD5, HMAC-SHA-1, or others. As authenticating the whole packet causes a heavy burden in the computation, RISAV defines that it only authenticates the IP source address, IP destination address, and the IP prefix length in ROA, SPI, and Sequence Number Field. The eventual signature is the hash of the 5-tuple before with the key/tag.

When a packet arrives at the source ASBR, it will be checked with the destination address by this ASBR first. If the destination address is in the protection range of RISAV, the packet will be checked by the source address next. If the source address belongs to the AS in which the ASBR locates, the packet needs to be filled in the AH header.

When a packet arrives at the destination ASBR, it will be checked the destination address and the source address orderly. If the destination belongs to the AS that the destination ASBR locates in and the source address seats in the RISAV protection area, the packet needs to be inspected with the AH header.

## Incremental deployment

So far, IPsec is often used as a VPN which is a technology for private network access through public networks. In the final analysis, IPsec is a highly cost-effective ratio mechanism. Original IPsec AH needs to authenticate the whole constant part of a packet so that it needs to spend amounts of time finding and processing unchangeable fields in the packet. However, RISAV only needs to find a few changeless fields to authenticate the packet decreasing the cost dramatically.

# Security Consideration

## Compatibility

When using RISAV, it WOULD be used at last when all other IPsec SA does not match. Such that, RISAV is comparable with the current IPsec Security Architecture. It SHOULD be guaranteed that the preference of RISAV is lower than other IPsec. So it may require the special SPI filled.

## Key Guessing and Cracking

For resisting label-based reply attacks, the eventual signature used in a packet is generated by the ASBR by hashing a few fields including the IP source address, IP destination address, and the IP prefix length in ROA, SPI, and Sequence Number Field. The attacker could guess the signature and crack that key using brute force. Nevertheless, it depends on the irreversibility of a hash function to prevent back stepping the key from the signature. Furthermore, to decrease such probability, the key used in generating the signature will be updated periodically.

# IANA Consideration

TBD.

<!-- # Acknowledgements -->
<!-- TBD. -->

--- back
