---

## This draft is the specific technology

title: 'An RPKI and IPsec-based AS-to-AS Approach for Source Address Validation'
abbrev: RISAV

docname: draft-xu-risav-latest

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

Source address spoofing is the practice of using a source IP address without proper authorization from its owner.  The basic internet routing architecture does not provide any defense against spoofing, so any system can send packets that claim any source address. This practice enables a variety of attacks, most notably volumetric DoS attacks as discussed in {{RFC2827}}.

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

## What RISAV Is

RISAV is a cryptographically-based inter-AS source address validation protocol that provides clear security benefits even at partial deployment. It aims to prove that each IP datagram was sent from inside the AS that owns its source address, defeating spoofing and replay attacks.  It is light-weight and efficient, and provides incremental deployment incentives.

At the source AS Border Router, RISAV adds a MAC to each packet that proves ownership of the packet's source address.  At the recipient's ASBR, RISAV verifies and removes this MAC, recovering the unmodified original packet. The MAC is delivered in the Integrity Check Value (ICV) field of a modified IPsec AH, or as part of the normal IPsec ESP payload.

## How RISAV Works

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

The functions of the control plane of RISAV include:

* Announcing that this AS supports RISAV.
* Publishing contact IPs.
* Performing IPsec session initialization (i.e. IKEv2).

These functions are achieved in two steps.  First, each participating AS publishes a Signed Object {{!RFC6488}} in its RPKI Repository containing a `RISAVAnnouncement`:

~~~ASN.1
RISAVAnnouncement ::= SEQUENCE {
         version [0] INTEGER DEFAULT 0,
         asID ASID,
         contactIP ipAddress,
         testing BOOLEAN }
~~~

When a participating AS discovers another participating AS (via its regular sync of the RPKI database), it initiates an IKEv2 handshake between its own contact IP and the other AS's contact IP.  This handshake MUST include an IKE_AUTH exchange that authenticates both ASes with their RPKI ROA certificates.

Once this handshake is complete, each AS MUST activate RISAV on all outgoing packets, and SHOULD drop all non-RISAV traffic from the other AS after a reasonable grace period (e.g. 60 seconds).

The "testing" field indicates whether this contact IP is potentially unreliable.  When this field is set to `true`, other ASes MUST fall back to ordinary operation if IKE negotiation fails.  Otherwise, the contact IP is presumed to be fully reliable, and other ASes SHOULD drop all non-RISAV traffic from this AS if IKE negotiation fails (see {{downgrade}}).

For more information about RPKI, see {{RFC6480}}.


## Disabling RISAV

To disable RISAV, a participating AS MUST perform the following steps in order:

1. Stop requiring RISAV authentication of incoming packets.
2. Remove the `RISAVAnnouncement` from the RPKI Repository.
3. Wait at least 24 hours.
4. Stop sending RISAV and shut down the contact IP.

Conversely, if any AS no longer publishes a `RISAVAnnouncement`, other ASes MUST immediately stop sending RISAV to that AS, but MUST NOT delete any negotiated Tunnel Mode SAs for at least 24 hours, in order to continue to process encrypted incoming traffic.

> TODO: Discuss changes to the contact IP, check if there are any race conditions between activation and deactivation, IKEv2 handshakes in progress, SA expiration, etc.

> SA has its own expiration time and IKE has its keepalive mechanism. In abnormal case, i.e. the connection is failed after the IKE handshake is established, SA will be always in effect during its lifetime until it expires or the IKE keepalive is failed. In normal case, i.e. the connection is actively down, SA will be expired and RISAV will be disabled immediately.

> OPEN QUESTION: Does IKEv2 have an authenticated permanent rejection option that would help here?

## Green Channel

In the event of a misconfiguration or loss of state, it is possible that a negotiated SA could become nonfunctional before its expiration time.  For example, if one AS is forced to reset its ACS and ASBRs, it may lose the private keys for all active RISAV SAs.  If RISAV were applied to the IKEv2 traffic used for bootstrapping, the participating ASes would be unable to communicate until these broken SAs expire, likely after multiple hours or days.

To ensure that RISAV participants can rapidly recover from this error state, RISAV places control plane traffic in a "green tunnel" that is exempt from RISAV's protections.  This "tunnel" is defined by two requirements:

* RISAV senders MUST NOT add RISAV protection to packets to or from any announced contact IP
* RISAV recipients MUST NOT enforce RISAV validation on packets sent to or from any announced contact IP.

Although the green tunnel denies RISAV protection to the ACS, the additional mitigations described in {data-plane} ensure that the ACS has limited exposure to address-spoofing and DDoS attacks. In addition, the ACS can use the IKEv2 COOKIE {{?RFC7296, Section 2.6}} and PUZZLE {{?RFC8019}} systems to reject attacks based on source address spoofing.

# Data Plane

All the ASBRs of the AS are REQUIRED to enable RISAV. The destination ASBR uses the IPsec SPI to locate the correct SA.

As defined in {{RFC4301}}, the Security Association Database (SAD) stores all the SAs. Each data item in the SAD includes a cryptographic algorithm (e.g. HMAC-SHA-256), its corresponding key, and other relevant parameters.

When an outgoing packet arrives at the source ASBR, its treatment depends on the source and destination address. If the source address belongs to the AS in which the ASBR is located, and the destination address is in an AS for which the ASBR has an active RISAV SA, then the packet needs to be modified for RISAV.

The modification that is applied depends on whether IPsec "transport mode" or "tunnel mode" is active.  This is determined by the presence or absence of the USE_TRANSPORT_MODE notification in the IKEv2 handshake.  RISAV implementations MUST support transport mode, and MAY support tunnel mode.

> OPEN QUESTION: How do peers express a preference or requirement for transport or tunnel mode?

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

In RISAV's use of AH, the parties are normally expected to disable Sequence Number Checks during IKEv2 negotiation.  However, the RISAV AH header does contain a sequence number, and the parties MAY make use of it.

> QUESTION: How does one disable sequence number checking in IKEv2?  RFC 4302 says "if an SA establishment protocol such as IKE is employed, the receiver SHOULD notify the sender, during SA establishment, if the receiver will not provide anti-replay protection", but I can't find any explanation of how this notification happens.

The AS-scoped AH headers are only for AS-to-AS communication.  Sending ASes MUST NOT add such headers unless the receiving AS has explicitly opted to receive them.  Receiving ASes MUST strip off all such headers for packets whose destination is inside the AS, even if the AS is not currently inspecting the ICV values.

In transport mode, each AS's SA Database (SAD) is indexed by SPI and counterpart AS, regardless of the source and destination IPs.

Transport mode normally imposes a space overhead of 32 octets.

## Tunnel Mode

In tunnel mode, a RISAV sender ASBR wraps each outgoing packet in an ESP payload.  Each ASBR uses its own source address, and sets the destination address to the contact IP of the destination AS.

The contact IP decrypts all IPsec traffic to recover the original packets, which are forwarded to the correct destination.  After decryption, the receiving AS MUST check that the source IP and destination IP are in the same AS as the outer source and destination, respectively.

In tunnel mode, each ASBR maintains its own copy of the SA Database (SAD).  Each copy of the SAD is indexed by SPI and counterpart AS. If a valid ESP packet is received from an unknown IP address, the receiving AS SHOULD allocate a new replay defense window, subject to resource constraints.  This allows replay defense to work as usual.  (If the contact IP is implemented as an ECMP cluster, effective replay defense may require consistent hashing.)

Tunnel mode imposes a space overhead of 73 octets in IPv6.

> PROBLEM: ESP doesn't protect the source IP, so a packet could be replayed by changing the source IP.  Can we negotiate an extension to ESP that covers the IP header?  Or could we always send from the contact IP and encode the ASBR ID in the low bits of the SPI?

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

In Transport Mode, off-path attackers cannot spoof the source IPs of a participating AS, but any attacker with access to valid traffic can replay it (from anywhere), potentially enabling DoS attacks by replaying expensive traffic (e.g. TCP SYNs, QUIC Initials).  ASes that wish to have replay defense, and are willing to pay the extra data-plane costs, should prefer tunnel mode.

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

The ACS, represented by a contact IP, must be a high-availability, high-performance service to avoid outages.  This might be achieved by electing one distinguished ASBR as the ACS. The distinguished ASBR acting as an ACS will represent the whole AS to communicate with peer AS's ACS. This election takes place prior to the IKE negotiation. In this arrangement, an ASBR MUST be a BGP speaker before it is elected as the distinguished ASBR.

## Synchronizing Multiple ASBRs {#MPProblem}

In RISAV, all ASBRs of each AS must have the same Security Associations, because the recipient does not keep distinct state for each sending ASBR (except for the replay window in tunnel mode). For example, ASBRs cannot perform IKE negotiation independently.  Instead, the ACS is the entity that represents the AS to negotiate associations with other ASes.

To ensure coherent behavior across the AS, the ACS MUST deliver each SA to all ASBRs in the AS immediately after it is negotiated.  RISAV does not standardize a mechanism for this update broadcast.

During the SA broadcast, ASBRs will briefly be out of sync.  RISAV recommends a grace period to prevent outages during the update process.

## Performance

RISAV requires participating ASes to perform symmetric cryptography on every RISAV-protected packet that they originate or terminate.  This will require significant additional compute capacity that may not be present on existing networks.  However, until most ASes actually implement RISAV, the implementation cost for the few that do is greatly reduced.  For example, if 5% of networks implement RISAV, then participating networks will only need to apply RISAV to 5% of their traffic.

Thanks to broad interest in optimization of IPsec, very high performance implementations are already available.  For example, as of 2021 an IPsec throughput of 1 Terabit per second was achievable using optimized software on a single server {{INTEL}}.

## MTU

> TODO: Figure out what to say about MTU, PMTUD, etc.  Perhaps an MTU probe is required after setup?  Or on an ongoing basis?

## NAT scenario

As all the outer IP header should be the unicast IP address, NAT-traversal mode is not necessary in inter-AS SAV.

# IANA Consideration

> TODO: Register RISAVAnnouncement.

<!-- # Acknowledgements -->
<!-- TBD. -->

--- back
