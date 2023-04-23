---

## This draft is the specific technology

title: 'An RPKI and IPsec-based AS-to-AS Approach for Source Address Validation'
abbrev: RISAV

docname: draft-xu-ipsecme-risav-latest

# stand_alone: yes

ipr: trust200902
# area: Security Area
stream: IETF
wg: ipsecme
kw: Internet-Draft
cat: std

coding: us-ascii
pi:    # can use array (if all yes) or hash here

toc: yes
sortrefs: yes  # defaults to yes
symrefs: yes

updates: 4302

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
        email: ietf@bemasc.net
      -
        name: Haiyang (Henry) Wang
        org: The University of Minnesota at Duluth
        city: Minnesota
        country: USA
        email: haiyang@d.umn.edu


normative:
  RFC2119:
  RFC2827:
  #RFC2986:
  #RFC3948:
  RFC4301:
  RFC4302:
  RFC4303:
  RFC5210:
  RFC5635:
  RFC5905:
  #RFC5996:
  RFC6278:
  RFC6480:
  RFC7039:
  RFC7296:
  RFC8174:
  RFC8209:
  #RFC8247:
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

Source address spoofing is the practice of using a source IP address without proper authorization from its owner.  The basic Internet routing architecture does not provide any defense against spoofing, so any system can send packets that claim any source address. This practice enables a variety of attacks, and we have summarized malicious attacks launched or amplified by spoofing address in appendix {{appendixA}}.

There are many possible approaches to preventing address spoofing. {{Section 2.1 of RFC5210}} describes three classes of Source Address Validation (SAV): Access Network, Intra-AS, and Inter-AS. Inter-AS SAV is the most challenging class, because different ASes have different policies and operate independently. Inter-AS SAV requires the different ASes to collaborate to verify the source address. However, in the absence of total trust between all ASes, Inter-AS SAV is a prerequisite to defeat source address spoofing.

Despite years of effort, current Inter-AS SAV protocols are not widely deployed. An important reason is the difficulty of balancing the clear security benefits of partial implementations with the scalability of large-scale deployments. uRPF {{RFC5635}} {{RFC8704}}, for example, is a routing-based scheme that filters out spoofed traffic.  In cases where the routing is dynamic or unknown, uRPF deployments must choose between false negatives (i.e. incomplete SAV) and false positives (i.e. broken routing).

This document provides an RPKI- {{RFC6480}} and IPsec-based {{RFC4301}} approach to inter-AS source address validation (RISAV). RISAV is a cryptography-based SAV mechanism to reduce the spoofing of source addresses. In RISAV, the RPKI database acts as a root of trust for IPsec between participating ASes.  Each pair of ASes uses IKEv2 to negotiate an IPsec Security Association (SA). Packets between those ASes are then protected by a modified IPsec Authentication Header (AH) {{RFC4302}} or an Encapsulating Security Payload (ESP){{RFC4303}}. IPsec authenticates the source address, allowing spoofed packets to be dropped at the border of the receiving AS.

## Requirements Language

{::boilerplate bcp14-tagged}


## Terminology

Commonly used terms in this document are described below.

ACS:
: AS Contact Server, which is the logical representative of one AS and is responsible for delivering session keys and other information to ASBR.

Contact IP:
: The IP address of the ACS.

ASBR:
: AS border router, which is at the boundary of an AS.

SAV:
: Source Address Validation, which verifies the source address of an IP packet and guarantee the source address is valid.

# Overview

The goal of this section is to provides the high level description of what RISAV is and how RISAV works.

## What RISAV Is and Is Not

RISAV is a cryptographically-based inter-AS source address validation protocol that provides clear security benefits even at partial deployment. It aims to prove that each IP datagram was sent from inside the AS that owns its source address, defeating spoofing and replay attacks.  It is light-weight and efficient, and provides incremental deployment incentives.

At the source AS Border Router, RISAV adds a MAC to each packet that proves ownership of the packet's source address.  At the recipient's ASBR, RISAV verifies and removes this MAC, recovering the unmodified original packet. The MAC is delivered in the Integrity Check Value (ICV) field of a modified IPsec AH, or as part of the normal IPsec ESP payload.

RISAV is not used to provide encription of the whole packet. It also does not aim to defense specific network attacks such as DoS or DDoS.

## How RISAV Works

RPKI{{!RFC6480}} is the prerequiste of RISAV. RISAV uses RPKI to bind the AS number and IP prefix. The binding relationship is formatted to ROA{{!RFC6482}}.

RISAV uses IKEv2 to negotiate an IPsec security association (SA) between any two ASes. RPKI provides the binding relationship between AS numbers, IP ranges, contact IPs, and public keys. After negotiation, all packets between these ASes are secured by use of a modified AH header or a standard ESP payload.

Before deploying RISAV, each AS selects one or more representative contact IPs, and publishes them in the RPKI database. When negotiating or consulting with one AS, the peer MUST first communicate with one of these contact IPs.  Each contact IP is used to enable RISAV only for its own address family (i.e. IPv4 or IPv6), so ASes wishing to offer RISAV on both IPv4 and IPv6 must publish at least two contact IPs.

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

1. RPKI process. The five Regional Internet Registries (RIR), authorized by IANA, use their root certificate to sign the Certificate Authority (CA) certificate of the Local Internet Registry (LIR), which is used to authorize the Autonomous System (AS) (sometimes indirectly via the Internet Service Provider (ISP)). When they obtain their own CA certificate, the AS would sign an End Entity (EE) certificate with a Route Origin Authorisation (ROA) which is a cryptographically signed object that states which AS are authorized to originate a certain prefix. This authenticated binding of the ASN to its IP prefixes is published in the RPKI database. This is a prerequisite for RISAV.

2. ACS EE certificate provisioning. The ACS would need its own EE certificate for IKEv2. This EE certificate is REQUIRED like the BGPsec Router Certificate defined in {{RFC8209}}.

3. RISAV announcement. Each participating AS announces its support for RISAV in the RPKI database, including the IP address of its ACS (the "contact IP").

4. SA negotiation and delivery. The ACSes negotiate an SA using IKEv2. After synchronization, all ASBRs would get the SA, including the session key and other parameters.

5. IPsec communication. RISAV uses IPsec AH (i.e. "transport mode") for authentication of the IP source address by default. When an ASBR in AS A sends a packet to AS B, it uses the established IPsec channel to add the required AH header. The ASBR in AS B validates the AH header to ensure that the packet was not spoofed, and removes the header.

# Control Plane

The functions of the control plane of RISAV include enabling and disabling RISAV, and it provides a green channel for quickly restarting the system in exception cases.

## Enabling RISAV
When RISAV is to be enabled, it should:

* announce that this AS supports RISAV,
* publish contact IPs,
* and perform IPsec session initialization (i.e. IKEv2).

<!--
TODO: we may need to enrich this process and describe ASN.1 format of RISAVAnnouncement with more details.
1. ITU - Introduction to ASN.1: https://www.itu.int/en/ITU-T/asn1/Pages/introduction.aspx
2. RFC 6025 - ASN.1 Translation: https://www.rfc-editor.org/rfc/rfc6025
3. RFC 3641 - Generic String Encoding Rules (GSER) for ASN.1 Types: https://www.rfc-editor.org/rfc/rfc3641.html
4. RFC 6268 - Additional New ASN.1 Modules for the Cryptographic Message Syntax (CMS) and the Public Key Infrastructure Using X.509 (PKIX): https://www.rfc-editor.org/rfc/rfc6268
-->

These functions are achieved in two steps.  First, each participating AS publishes a Signed Object {{!RFC6488}} in its RPKI Repository containing a `RISAVAnnouncement`, which is the only thing that RISAV uses RPKI different from traditional RPKI. The ASN.1 formation of `RISAVAnnouncement` is as follows:

~~~ASN.1
RISAVAnnouncement ::= SEQUENCE {
         version [0] INTEGER DEFAULT 0,
         asID ASID,
         contactIP IPAddress,
         testing BOOLEAN }
ASID              ::= BIT STRING
IPAddress         ::= BIT STRING
~~~

When a participating AS discovers another participating AS (via its regular sync of the RPKI database), it initiates an IKEv2 handshake between its own contact IP and the other AS's contact IP.  This handshake MUST include an IKE_AUTH exchange that authenticates both ASes with their RPKI ROA certificates.

Once this handshake is complete, each AS MUST activate RISAV on all outgoing packets, and SHOULD drop all non-RISAV traffic from the other AS after a reasonable grace period (e.g. 60 seconds).

The "testing" field indicates whether this contact IP is potentially unreliable.  When this field is set to `true`, other ASes MUST fall back to ordinary operation if IKE negotiation fails.  Otherwise, the contact IP is presumed to be fully reliable, and other ASes SHOULD drop all non-RISAV traffic from this AS if IKE negotiation fails (see {{downgrade}}).

RISAV just adds one `RISAVAnnouncement` to the repository of RPKI. The other procedure is the same as the traditional RPKI. For more information about RPKI, see {{RFC6480}}.


## Disabling RISAV

### Targeted shutdown

IKEv2 SAs can be terminated on demand using the Delete payload ({{RFC7296, Section 1.4.1}}).  In ordinary uses of IKEv2, the SAs exist in inbound-outbound pairs, and deletion of one triggers a response deleting the other.

In RISAV, SAs do not necessarily exist in pairs.  Instead, RISAV's use of IPsec is strictly unidirectional, so deletion does not trigger an explicit response.  Instead, ASes are permitted to delete both inbound and outbound SAs, and deletion of an inbound SA SHOULD cause the other network to retry RISAV negotiation.  If this, or any, RISAV IKEv2 handshake fails with a NO_ADDITIONAL_SAS notification ({{RFC7296, Section 1.3}}), the following convention applies:

* AS $A is said to have signaled a "RISAV shutdown" to $B if it sends NO_ADDITIONAL_SAS on a handshake with no child SAs.
* In response, $B MUST halt all further RISAV negotiation to $A until:
  - At least one hour has passed, OR
  - $A negotiates a new SA from $A to $B.
* After at most 24 hours, $B SHOULD resume its regular negotiation policy with $A.

This convention enables participating ASes to shut down RISAV with any other AS, by deleting all SAs and rejecting all new ones.  It also avoids tight retry loops after a shutdown has occurred, but ensures that RISAV is retried at least once a day.

### Total shutdown

To disable RISAV entirely, a participating AS MUST perform the following steps in order:

1. Apply a targeted shutdown ({{targeted-shutdown}}) to all other networks and delete all existing SAs.
  - Note that the shutdown procedure can fail if another network's ACS is unreachable.
1. Stop requiring RISAV authentication of incoming packets.
1. Remove the `RISAVAnnouncement` from the RPKI Repository.
1. Wait at least 24 hours.
1. Shut down the contact IP.

Conversely, if any AS no longer publishes a `RISAVAnnouncement`, other ASes MUST immediately stop sending RISAV to that AS, but MUST NOT delete any active Tunnel Mode SAs for at least 24 hours, in order to continue to process encrypted incoming traffic.

> TODO: Discuss changes to the contact IP, check if there are any race conditions between activation and deactivation, IKEv2 handshakes in progress, SA expiration, etc.

## Green Channel

In the event of a misconfiguration or loss of state, it is possible that a negotiated SA could become nonfunctional before its expiration time.  For example, if one AS is forced to reset its ACS and ASBRs, it may lose the private keys for all active RISAV SAs.  If RISAV were applied to the IKEv2 traffic used for bootstrapping, the participating ASes would be unable to communicate until these broken SAs expire, likely after multiple hours or days.

To ensure that RISAV participants can rapidly recover from this error state, RISAV places control plane traffic in a "green channel" that is exempt from RISAV's protections.  This "channel" is defined by two requirements:

* RISAV senders MUST NOT add RISAV protection to packets to or from any announced contact IP
* RISAV recipients MUST NOT enforce RISAV validation on packets sent to or from any announced contact IP.

Although the green channel denies RISAV protection to the ACS, the additional mitigations described in {{data-plane}} ensure that the ACS has limited exposure to address-spoofing and DDoS attacks. In addition, the ACS can use the IKEv2 COOKIE ({{Section 2.6 of RFC7296}}) and PUZZLE ({{?RFC8019}}) systems to reject attacks based on source address spoofing.

# Data Plane

All the ASBRs of the AS are REQUIRED to enable RISAV. The destination ASBR uses the IPsec SPI to locate the correct SA.

As defined in {{RFC4301}}, the Security Association Database (SAD) stores all the SAs. Each data item in the SAD includes a cryptographic algorithm (e.g. HMAC-SHA-256), its corresponding key, and other relevant parameters.

When an outgoing packet arrives at the source ASBR, its treatment depends on the source and destination address. If the source address belongs to the AS in which the ASBR is located, and the destination address is in an AS for which the ASBR has an active RISAV SA, then the packet needs to be modified for RISAV.

The modification that is applied depends on whether IPsec "transport mode" or "tunnel mode" is active.  RISAV implementations MUST support transport mode, and MAY support tunnel mode.  The initiator chooses the mode by including or omitting the USE_TRANSPORT_MODE notification in the IKEv2 handshake, retrying in the other configuration if necessary.

When a packet arrives at the destination ASBR, it will check the destination address and the source address. If the destination belongs to the AS in which the destination ASBR is located, and the source address is in an AS with which this AS has an active RISAV SA, then the packet is subject to RISAV processing.

To avoid DoS attacks, participating ASes MUST drop any outgoing packet to the contact IP of another AS.  Only the AS operator's systems (i.e. the ACS and ASBRs) are permitted to send packets to the contact IPs of other ASes.  ASBRs MAY drop inbound packets to the contact IP from non-participating ASes.

## Transport Mode

To avoid conflict with other uses of IPsec ({{conflict}}), RISAV updates the IPsec Authentication Header (AH) format, converting one RESERVED octet (which is previously required to always be zero) into a new "Scope" field.  The updated format is shown in {{fig2}}.

~~~~~~~~~~~
                     1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Header   |  Payload Len  |   RESERVED    |     Scope     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Security Parameters Index (SPI)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number Field                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                Integrity Check Value-ICV (variable)           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~~
{: #fig2 title="Updated AH Format."}

The "Scope" field identifies the scope of protection for this authentication header, i.e. the entities that are expected to produce and consume it.  Two Scope values are defined:

* 0: IP.  This is the pre-existing use of the Authentication Header, to authenticate packets from the source IP to the destination IP.
* 1: AS.  This header authenticates the packet from the source AS to the destination AS.

Other Scope values could be defined in the future.

The AS-scoped AH headers are only for AS-to-AS communication.  Sending ASes MUST NOT add such headers unless the receiving AS has explicitly opted to receive them.  Receiving ASes MUST strip off all such headers for packets whose destination is inside the AS, even if the AS is not currently inspecting the ICV values.

Transport mode normally imposes a space overhead of 32 octets.

### ICMP rewriting

There are several situations in which an intermediate router on the path may generate an ICMP response to a packet, such as a Packet Too Big (PTB) response for Path MTU Discovery, or a Time Exceeded message for Traceroute.  These ICMP responses generally echo a portion of the original packet in their payload.

An ASBR considers an ICMP payload to match a Transport Mode RISAV SA if:

1. The payload's source address is in this AS, AND
2. The payload's destination address is in the other AS, AND
3. The payload contains a RISAV AH header whose SPI matches the SA's.

When an ASBR observes a matching ICMP response, it MUST forward it to the intended recipient, with the following modifications:

* The ASBR MUST remove the RISAV AH header from the payload, so that the echoed payload data matches the packet sent by the original sender.
* When processing a Packet Too Big message, the ASBR MUST reduce the indicated `MTU` value by the total length of the RISAV AH header.

These changes ensure that RISAV remains transparent to the endpoints, similar to the ICMP rewriting required for Network Address Translation {{?RFC5508}} (though much simpler).

## Tunnel Mode

In tunnel mode, a RISAV sender ASBR wraps each outgoing packet in an ESP payload ({{RFC4303}}) and sends it as directed by the corresponding SA.  This may require the ASBR to set the Contact IP as the source address, even if it would not otherwise send packets from that address.  (See also "Anycast", {{reliability}}).

Tunnel mode imposes a space overhead of 73 octets in IPv6.

# MTU Handling

Like any IPsec tunnel, RISAV normally reduces the effective IP Maximum Transmission Unit (MTU) on all paths where RISAV is active.  To ensure standards compliance and avoid operational issues, participating ASes MUST choose a minimum acceptable "inner MTU", and reject any RISAV negotiations whose inner MTU would be lower.

There are two ways for a participating AS to compute the inner MTU:

1. **Prior knowledge of the outer MTU**.  If a participating AS knows the minimum outer MTU on all active routes to another AS (e.g., from the terms of a transit or peering agreement), it SHOULD use this information to calculate the inner MTU of a RISAV SA with that AS.
1. **Estimation of the outer MTU**.  If the outer MTU is not known in advance, the participating ASes MUST estimate and continuously monitor the MTU, disabling the SA if the inner MTU falls below the minimum acceptable value.  An acceptable MTU estimation procedure is described in {{mtu-estimation}}.

If the minimum acceptable inner MTU is close or equal to a common outer MTU value (e.g., 1500 octets), RISAV will not be usable in its baseline configuration.  To enable larger inner MTUs, participating ASes MAY offer support for AGGFRAG {{!RFC9347}} in the IKEv2 handshake if they are able to deploy it (see {{ts-replay}}).

## MTU Enforcement

In tunnel mode, RISAV ASBRs MUST treat the tunnel as a single IP hop whose MTU is given by the current (estimated) inner MTU.  Oversize packets that reach the ASBR SHALL generate Packet Too Big (PTB) ICMP responses (or be fragmented forward, in IPv4) as usual.

In transport mode, RISAV ASBRs SHOULD NOT enforce the estimated inner MTU.  Instead, ASBRs SHOULD add RISAV headers and attempt to send packets as normal, regardless of size.  (This may cause a PTB ICMP response at the current router or a later hop, which is modified and forwarded as described in {{icmp-rewriting}}.)

In either mode, the ASBR SHOULD apply TCP MSS clamping {{!RFC4459, Section 3.2}} to outbound packets based on the current estimated inner MTU.

## MTU Estimation

This section describes an MTU estimation procedure that is considered acceptable for deployment of RISAV.  Other procedures with similar performance may also be acceptable.

### Step 1: Initial estimate

To compute an initial estimate, the participating ASes use IKEv2 Path MTU Discovery (PMTUD) {{?RFC7383, Section 2.5.2}} between their ACSes during the IKEv2 handshake.  However, unlike the recommendations in {{RFC7383}}, the PMTUD process is performed to single-octet granularity.  The IKEv2 handshake only proceeds if the resulting outer MTU estimate is compatible with the minimum acceptable inner MTU when using the intended SA parameters.

### Step 2: MTU monitoring

The initial MTU estimate may not be correct indefinitely:

* The Path MTU may change due to a configuration change in either participating AS.
* The Path MTU may change due to a routing change outside of either AS.
* The Path MTU may be different for packets to or from different portions of the participating ASes.

To ensure that the MTU estimate remains acceptable, and allow for different MTUs across different paths, each ASBR maintains an MTU estimate for each active SA, and updates its MTU estimate whenever it observes a PTB message.  The ASBR's procedure is as follows:

1. Find the matching SA ({icmp-rewriting}) for this PTB message.  If there is none, abort.
1. Check the SA's current estimated outer MTU against the PTB MTU.  If the current estimate is smaller or equal, abort.
1. Perform an outward Traceroute to the PTB payload's destination IP, using packets whose size is the current outer MTU estimate, stopping at the first IP that is equal to the PTB message's sender IP or is inside the destination AS.
1. If a PTB message is received, reduce the current MTU estimate accordingly.
1. If the new estimated inner MTU is below the AS's minimum acceptable MTU, notify the ACS to tear down this SA.

Note that the PTB MTU value is not used, because it could have been forged by an off-path attacker.  To preclude such attacks, all Traceroute and PMTUD probe packets contain at least 16 bytes of entropy, which the ASBR checks in the echoed payload.

To prevent wasteful misbehaviors and reflection attacks, this procedure is rate-limited to some reasonable frequency (e.g., at most once per minute per SA).

# Traffic Selectors and Replay Protection in RISAV {#ts-replay}

The IKEv2 configuration protocol is highly flexible, allowing participating ASes to negotiate many different RISAV configurations.  For RISAV, two important IKEv2 parameters are the Traffic Selector ({{RFC7296, Section 2.9}}) and the Replay Status.

> TODO: Write draft porting Replay Status from RFC 2407 to IKEv2.

## Disabling replay protection

In the simplest RISAV configuration, the sending AS requests creation of a single "Child SA" whose Traffic Selector-initiator (TSi) lists all the IP ranges of the sending AS, and the Traffic Selector-responder (TSr) lists all the IP ranges of the receiving AS.  This allows a single SA to carry all RISAV traffic from one AS to another.  However, this SA is likely to be shared across many ASBRs, and potentially many cores within each ASBR, in both participating ASes.

It is difficult or impossible for a multi-sender SA to use monotonic sequence numbers, as required for anti-replay defense and Extended Sequence Numbers (ESN) (see {{RFC4303, Section 2.2}}).  If the sender cannot ensure correctly ordered sequence numbers, it MUST set the REPLAY-STATUS indication to FALSE in the CREATE_CHILD_SA notification, and MUST delete the SA if the recipient does not confirm that replay detection is disabled.

## Enabling replay protection

If the sender wishes to allow replay detection, it can create many Child SAs, one for each of its ASBRs (or each core within an ASBR).  The OPTIONAL `CPU_QUEUES` IKEv2 notification {{?I-D.ietf-ipsecme-multi-sa-performance}} may make this process more efficient.  If the sending ASBRs are used for distinct subsets of the sender's IP addresses, the TSi values SHOULD be narrowed accordingly to allow routing optimizations by the receiver.

Even if the sender creates many separate SAs, the receiver might not be able to perform replay detection unless each SA is processed by a single receiving ASBR.  In Tunnel Mode, the receiver can route each SA to a specific ASBR using IKEv2 Active Session Redirect ({{?RFC5685, Section 5}}).

In Transport Mode, assignment of SAs to receiving ASBRs may be possible in cases where each ASBR in the receiving AS is responsible for a distinct subset of its IPs.  To support this configuration, the receiving AS MAY narrow the initial TSr to just the IP ranges for a single ASBR, returning ADDITIONAL_TS_POSSIBLE.  In response, the sending AS MUST reissue the CREATE_CHILD_SA request, with TSr containing the remainder of the IP addresses, allowing the negotiation of separate SAs for each receiving ASBR.

Future IKEv2 extensions such as Sequence Number Subspaces {{?I-D.ponchon-ipsecme-anti-replay-subspaces}} or Lightweight SAs {{?I-D.mrossberg-ipsecme-multiple-sequence-counters}} may enable more efficient and easily deployed anti-replay configurations for RISAV.

## Changes to AS IP ranges

If the ACS receives a TSi value that includes IP addresses not owned by the counterpart AS, it MUST reject the SA to prevent IP hijacking.  However, each AS's copy of the RPKI database can be up to 24 hours out of date.  Therefore, when an AS acquires a new IP range, it MUST wait at least 24 hours before including it in a RISAV TSi.

If a tunnel mode SA is established, the receiving AS MUST drop any packet from the tunnel whose source address is not within the tunnel's TSi.

# Possible Extensions

This section presents potential additions to the design.

> TODO: Remove this section once we have consensus on whether these extensions are worthwhile.

## Header-only authentication

An IPsec Authentication Header authenticates the whole constant part of a packet, including the entire payload. To improve efficiency, we could define an IKE parameter to negotiate a header-only variant of transport mode that only authenticates the IP source address, IP destination address, etc.

This would likely result in a 10-30x decrease in cryptographic cost compared to standard IPsec.  However, it would also offer no SAV defense against any attacker who can view legitimate traffic.  An attacker who can read a single authenticated packet could simply replace the payload, allowing it to issue an unlimited number of spoofed packets.

## Time-based key rotation

Each IKEv2 handshake negotiates a fixed shared secret, known to both parties. In some cases, it might be desirable to rotate the shared secret frequently:

* In transport mode, frequent rotation would limit how long a single packet can be replayed by a spoofing attacker.
* If the ASBRs are less secure than the ACS, frequent rotation could limit the impact of a compromised ASBR.

However, increasing the frequency of IKEv2 handshakes would increase the burden on the ACS. One alternative possibility is to use a state machine. The state machine runs and triggers the state transition when time is up. The tag is generated in the process of state transition as the side product. The two ACS in peer AS respectively before data transmission will maintain one state machine pair for each bound. The state machine runs simultaneously after the initial state, state transition algorithm, and state transition interval are negotiated, thus they generate the same tag at the same time. Time triggers state transition which means the ACS MUST synchronize the time to the same time base using like NTP defined in {{RFC5905}}.

For the tag generation method, it MUST be to specify the initial state and initial state length of the state machine, the identifier of a state machine, state transition interval, length of generated Tag, and Tag. For the SA, they will transfer all these payloads in a secure channel between ACS and ASBRs, for instance, in ESP {{RFC4303}}. It is RECOMMENDED to transfer the tags rather than the SA for security and efficiency considerations. The initial state and its length can be specified at the Key Exchange Payload with nothing to be changed. The state machine identifier is the SPI value as the SPI value is uniquely in RISAV. The state transition interval and length of generated Tag should be negotiated by the pair ACS, which will need to allocate one SA attribute. The generated Tag will be sent from ACS to ASBR in a secure channel which MAY be, for example, ESP {{RFC4303}}.

## Static Negotiation

The use of IKEv2 between ASes might be fragile, and creates a number of potential race conditions (e.g. if the RPKI database contents change during the handshake).  It is also potentially costly to implement, requiring O(N^2) network activity for N participating ASes.  If these challenges prove significant, one alternative would be to perform the handshake statically via the RPKI database.  For example, static-static ECDH {{RFC6278}} would allow ASes to agree on shared secrets simply by syncing the RPKI database.

Static negotiation makes endpoints nearly stateless, which simplifies the provisioning of ASBRs.  However, it requires inventing a novel IPsec negotiation system, so it seems best to try a design using IKEv2 first.

# Security Consideration

## Threat models

In general, RISAV seeks to provide a strong defense against arbitrary active attackers who are external to the source and destination ASes.  However, different RISAV modes and configurations offer different security properties.

### Replay attacks

When replay detection is disabled, off-path attackers cannot spoof the source IPs of a participating AS, but any attacker with access to valid traffic can replay it (from anywhere), potentially enabling DoS attacks by replaying expensive traffic (e.g. TCP SYNs, QUIC Initials).  ASes that wish to have replay defense must enable it during the IKEv2 handshake (see {{ts-replay}}).

### Downgrade attacks {#downgrade}

An on-path attacker between two participating ASes could attempt to defeat RISAV by blocking IKEv2 handshakes to the Contact IP of a target AS.  If the AS initiating the handshake falls back to non-RISAV behavior after a handshake failure, this enables the attacker to remove all RISAV protection.

This vulnerable behavior is required when the "testing" flag is set, but is otherwise discouraged.

## Incremental benefit from partial deployment

RISAV provides significant security benefits even if it is only deployed by a fraction of all ASes.  This is particularly clear in the context of reflection attacks.  If two networks implement RISAV, no one in any other network can trigger a reflection attack between these two networks.  Thus, if X% of ASes (selected at random) implement RISAV, participating ASes should see an X% reduction in reflection attack traffic volume.

## Compatibility

### With end-to-end IPsec {#conflict}

When RISAV is used in transport mode, there is a risk of confusion between the RISAV AH header and end-to-end AH headers used by applications.  (In tunnel mode, no such confusion is possible.)  This risk is particularly clear during transition periods, when the recipient is not sure whether the sender is using RISAV or not.

To prevent any such confusion, RISAV's transport mode uses a distinctive Scope value in the Authentication Header.  The receiving AS absorbs (and strips) all AH headers with this scope, and ignores those with any other scope, including ordinary end-to-end AH headers.

### With other SAV mechanisms

RISAV is independent from intra-domain SAV and access-layer SAV, such as {{RFC8704}} or SAVI {{RFC7039}}. When these techniques are used together, intra-domain and access-layer SAV checks MUST be enforced before applying RISAV.

# Operational Considerations

## Reliability

The ACS, represented by a contact IP, must be a high-availability, high-performance service to avoid outages.  There are various strategies to achieve this, including:

* **Election**. This might be achieved by electing one distinguished ASBR as the ACS. The distinguished ASBR acting as an ACS will represent the whole AS to communicate with peer AS's ACS. This election takes place prior to the IKE negotiation. In this arrangement, an ASBR MUST be a BGP speaker before it is elected as the distinguished ASBR, and a new election MUST replace the ACS if it fails.
* **Anycast**.  The ACS could be implemented as an anycast service operated by all the ASBRs.  Route flapping can be mitigated using IKEv2 redirection ({{?RFC5685, Section 4}}).  Negotiated SAs must be written into a database that is replicated across all ASBRs.

## Synchronizing Multiple ASBRs {#MPProblem}

To ensure coherent behavior across the AS, the ACS MUST deliver each SA to all relevant ASBRs in the AS immediately after it is negotiated.  RISAV does not standardize a mechanism for this update broadcast.

During the SA broadcast, ASBRs will briefly be out of sync.  RISAV recommends a grace period to prevent outages during the update process.

## Performance

RISAV requires participating ASes to perform symmetric cryptography on every RISAV-protected packet that they originate or terminate.  This will require significant additional compute capacity that may not be present on existing networks.  However, until most ASes actually implement RISAV, the implementation cost for the few that do is greatly reduced.  For example, if 5% of networks implement RISAV, then participating networks will only need to apply RISAV to 5% of their traffic.

Thanks to broad interest in optimization of IPsec, very high performance implementations are already available.  For example, as of 2021 an IPsec throughput of 1 Terabit per second was achievable using optimized software on a single server {{INTEL}}.

## NAT scenario

As all the outer IP header should be the unicast IP address, NAT-traversal mode is not necessary in inter-AS SAV.

# Consistency with Existing Standards

## IPv6

RISAV modifies the handling of IPv6 packets as they traverse the network, resulting in novel networking behaviors.  This section describes why those behaviors should not be viewed as violating the requirements of {{?RFC8200}}.

### MTU

{{Section 5 of ?RFC8200}} says:

> IPv6 requires that every link in the Internet have an MTU of 1280 octets or greater.  This is known as the IPv6 minimum link MTU.

RISAV adds ~30-80 octets of overhead to each packet, reducing the effective link MTU.  A naive version of RISAV could violate the 1280-octet rule, when running over a (compliant) path with a Path MTU of 1280 octets.

This violation is avoided by the requirements described in {{mtu-handling}}.  The resulting behavior is fully compliant when the underlying Path MTU is stable, and should compensate or disable RISAV within a few seconds if the Path MTU changes.

### Header modifications

{{Section 4 of ?RFC8200}} says:

> Extension headers (except for the Hop-by-Hop Options header) are not processed, inserted, or deleted by any node along a packet's delivery path, until the packet reaches the node (or each of the set of nodes, in the case of multicast) identified in the Destination Address field of the IPv6 header.

In "tunnel mode" ({{tunnel-mode}}), RISAV acts as a classic site-to-site tunnel, potentially adding its own extension headers.  {{Section 4.1 of ?RFC8200}} specifically allows such tunnels, and they are commonly used.

In "transport mode" ({{transport-mode}}), a RISAV ASBR does insert a new extension header, which could be viewed as a violation of this guidance.  However, this new extension header is an implementation detail of a lightweight tunnel: it is only added after confirming that another router on the path will remove it, so that its presence is not detectable by either endpoint.  ({{icmp-rewriting}} adds further requirements to ensure that this header cannot be detected in ICMP responses either.)

### IP address usage

In some RISAV configurations, it is expected that many ASBRs will decrypt and process packets with the destination IP of the ACS and/or emit packets using the source IP of the ACS.  This can be viewed as replacing the central ACS with an "anycast" service, which is generally considered permissible.

## RPKI Usage

{{?RFC9255}} describes limits on the use of RPKI certificates for new purposes, including the following excerpts:

> The RPKI was designed and specified to sign certificates for use within the RPKI itself and to generate Route Origin Authorizations (ROAs) \[RFC6480\] for use in routing. Its design intentionally precluded use for attesting to real-world identity...

> RPKI-based credentials of INRs MUST NOT be used to authenticate real-world documents or transactions.

> When a document is signed with the private key associated with an RPKI certificate, the signer is speaking for the INRs (the IP address space and AS numbers) in the certificate. ... If the signature is valid, the message content comes from a party that is authorized to speak for that subset of INRs.

RISAV's usage of RPKI key material falls squarely within these limits.  The RPKI signature used in the IKEv2 handshake serves only to confirm that this party is authorized to originate and terminate IP packets using the corresponding IP ranges.  The "identity" of this party is not relevant to RISAV.

# IANA Consideration

> TODO: Register RISAVAnnouncement.

<!-- # Acknowledgements -->
<!-- TBD. -->

--- back
# Appendix: Summary of Attacks {#appendixA}

The malicious attacks that launched by spoofing address can be classified into two parts: direct attack and amplification attack.

## Direct Attack

Direct attack is attacks that use spoofing address as the attack methodology. In this case, the packets sent out by attacker to victim would use the spoofed IP address as its source address. It is hard to locate the attackers. These attacks includes DoS, DDoS, SYN flooding, etc.

## Amplification Attack

Attackers would not send the packets to victim directly, but they would send packets to a server that runs amplification service, such as DNS, NTP, SNMP, SSDP, and other UDP/TCP-based services. In this case, packet sent to the public server would be multiplicated replyed to the victim, which would be more destructive than direct attack.
