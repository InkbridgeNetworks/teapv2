---
title: Tunnel Extensible Authentication Protocol (TEAP) Version 2
abbrev: TEAP
docname: draft-dekok-emu-teapv2-00

stand_alone: true
ipr: trust200902
area: Internet
wg: EMU working group
kw: Internet-Draft
cat: std
submissionType: IETF
obsoletes: 7170
updates: 9427

pi:    # can use array (if all yes) or hash here
  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:

- ins: A. DeKok
  name: Alan DeKok
  email: alan.dekok@inkbridge.io
  organization: InkBridge Networks

normative:
  BCP14: RFC8174
  RFC8446:
  RFC9427:
  I-D.ietf-emu-rfc7170bis:

informative:
  KAMATH:
     title: "Microsoft EAP CHAP Extensions"
     date: June 2007
     author:
       name: Ryan Hurst and Ashwin Palekar

venue:
  group: EMU
  mail: emu@ietf.org
  github: inkbridgenetworks/teapv2.git

--- abstract

This document defines the Tunnel Extensible Authentication Protocol
(TEAP) version 2.  It addresses a number of security and
interoperability issues in TEAPv1 which was defined in
{{I-D.ietf-emu-rfc7170bis}}.

--- middle

# Introduction

Tunnel Extensible Authentication Protocol (TEAP) version 1 was first
defined in {{?RFC7170}}.  However, implementations of that
specification were found to have limited interoperability, due to the
complexity and under-specification of the cryptographic key
deriviations defined there.

TEAPv1 was updated and clarified in {{I-D.ietf-emu-rfc7170bis}}.
That document defined a large amount of functionality in the protocol,
but also noted in (TBD) that only a small subset of that functionality
was interoperable.  In addition, the interoperable parts of the
protocol security issues which could allow on-path attackers
essentially unlimited control over the data being transported inside
of the TLS tunnel.

We do not review the full security issues with TEAPv1 here.  Instead,
we define new and simpler cryptographic key deriviations.  These
derivations address all of the known issues with TEAPv1.

# Negotiation

TBD: repeat the text in {{I-D.ietf-emu-rfc7170bis}} about version
negotiation.

TEAPv2 MUST be used with TLS 1.3 or later.

# Cryptographic Calculations

The cryptographic calculations for TEAPv2 address a number of issues
in TEAPv1:

* all inner exchanges are bound to the TLS tunnel

* all inner exchanges include a Crypto-Binding TLV

* inner exchanges which use a challenge (e.g. EAP-MSCHAPv2 {{KAMATH}})
  derive that challenge from the TLS parameters

* The cryptrographic deriviations have been substantially simplified

## TEAP Authentication Phase 1: Key Derivations {#key-derivations}

The session key seed is the same as for TEAPv1 (TBD)

~~~~
   session_key_seed = TLS-Exporter(
                      "EXPORTER: teap session key seed",, 40)
~~~~

## Intermediate Compound Key Derivations {#intermediate-compound-key}

Instead of using a complex key deriviation method as was done with
TEAPv1, TEAPv2 uses a much simpler method to derive the keys.  This
method is split into a few steps:

* define a seed which combines data from the current inner message,
  along with data from the previous round.

* Call the TLS-Exporter() function with the seed in order to derive
  keying data.

* Split the resulting keying data into subkeys, which are each used
  for different purposes.

Unlike TEAPv1, TEAPv2 mixes data from each inner message, and not from
each inner authentication method.  Some inner authentication methods
do not derive keys (e.g. Basic-Password-Req TLV and
Basic-Password-Resp TLV).  Other inner message exchanges such as the
CSR-Attributes TLV, PKCS#7 TLV, or PKCS#10 TLV also do not derive
keys.

Where TEAPv1 uses a Master Session Key (MSK) of all zeros for those
inner messages, TEAPv2 defines a pseudo MSK which is tied to the TLS
tunnel, and is derived from the data being exchanged.  This pseudo MSK
is then used in the cryptographic calculations, as with the MSK from
an inner method.

The keys for each inner message are then mixed with a seed from
previous rounds beginning with the TEAP Phase 2 session_key_seed
derived above, to yield a for set of keys for this round.  The seed
from the final round is then used to derive the MSK and EMSK for TEAP.

### Key Seeding

All intermediate compound key deriviations for TEAPv2 depend on the
same structure as input to the key deriviations.  For simplicity, we
define the structure using the same syntax as is used for TLS
{{RFC8446}}

~~~~
   struct {
       opaque PrevRoundKey[40]
       opaque MSK[32];
       opaque EMSK[32]
   } RoundSeed
~~~~

The above fields have the following definitions:

PrevRoundKey

> A key which ties the current exchange to the previous exchange.
>
> For the first round, this field is taken from the session_key_seed.
>
> For subsequent rounds, this field is set to the RoundKey which is
> part of the DerivedKey structure, as defined in the next section.

MSK

> The Master Session Key (MSK) from the inner message
> 
> If the MSK is longer than 32 octets, the extra octets are not used
> in this structure.
>
> If the inner method derives an EMSK but not an MSK, then this field
> MUST be initialized to all zeros.
>
> If the inner message does not perform authentication, or the inner
> authentication method does not derive an MSK or an EMSK, then a
> pseudo MSK is derived instead.  See (TBD) below for dicussion and
> definition of the pseudo MSK.
>
> This deriviation means that unlike TEAPv1, the MSK field is never
> zero, even for inner methods which do not derive an MSK.

EMSK

> The Extended Master Session Key (EMSK) from the inner method.
> 
> If the EMSK is longer than 32 octets, the extra octets are not used
> in this structure.
>
> If the inner method does not derive an EMSK, then this field is
> initialized to all zeros.

An inner message MUST derive either an MSK (including a pseudo MSK),
or an EMSK, or both.  The RoundSeed structure MUST NOT have both the
MSK and EMSK fields be all zeros.

### Key Derivation

Each round produces a DerivedKey, which is derived from the RoundSeed
for the this round via the following calculation.

~~~~
   DerivedKey = TLS-Exporter(RoundSeed,
                "EXPORTER: TEAPv2 Inner Methods Compound Keys", 104)
~~~~

The DerivedKey is 104 octets in length, and assigned to the following
structure:

~~~~
   struct {
       opaque RoundKey[40];
       opaque CMK[32]
       opaque Challenge[32]
   } RoundSeed
~~~~

The above fields have the following definitions:

RoundKey

> The key for this round, which is copied to the PrevRoundKey field in
> the RoundSeed structure, in order to seed the next round.

CMK

> The Compound MAC Key (CMK)
>
> The CMK is mixed with with various data from the TEAP negotiation to
> create the Compound-MAC field of the Crypto-Binding attribute.

Challenge

> The implicit challenge used for inner authentication methods such as
> EAP-MSCHAPv2.
>
> Unlike the implicit challenge in {{RFC9427, Section 2.4}}, this
> challenge is fixed size in length.  The inner method uses only as
> much of the Challenge as it needs, and the remainder of the
> Challenge is ignored.
>
> If the inner method does not use a challenge, then the Challenge
> field is ignored.

## Methods which do not generate MSK or EMSK

Where an inner message does not generate MSK (Basic-Password-Resp TLV
or PKCS#7 TLV), then a pseudo MSK is calculated which is derived from
the inner data.  This pseudo MSK ensures that the data from each
message is mixed in with the data from previous exchanges.  This
mixing cryptographically binds every inner message to the protected
tunnel (not just inner authentications), and binds each message to the
previous one.  This cryptographic binding prevents on-path attacks.

In contrast, TEAPv1 just sets the MSK to zero for these TLVs, which
does not tie the data to the TLS session, or prevent on-path
attackers.

~~~~
  MSK = TLS-Exporter(data,
        "EXPORTER: TEAPv2 Inner Method MSK", data_len)
~~~~

Where "data" is the contents of the TLV.  That is, everything encoded
in the TLV after the four octet TLV header.

* Basic-Password-Req TLV: Value

* Basic-Password-Resp TLV: Userlen, Username, Passlen, Password

* CSR-Attributes TLV: DER Encoded CSR Attributes

* PKCS#7 TLV: PKCS#7 Data

* PKCS#10 TLV: PKCS#10 Data

The sending party MUST inform the receiving party which TLVs are used
to calculate this pseudo MSK via the Pseudo-MSK-Contents TLV, which is
defined in (TBD), below.

This explicit signal makes implementations easier, because otherwise
each non-authentication exchange would require special-purpose code to
process it.  It also makes future extensions easier, as any additional
non-authentiction exchanges do can simply be listed in the
Pseudo-MSK-Contents TLV, and do not need special-purpose code.

## Computing the Compound-MAC {#computing-compound-mac}

The Compound-MAC used in the Crypto-Binding TLV is calculated exactly
the same as with TEAPv1:

~~~~
   Compound-MAC = the first 20 octets of MAC( CMK, BUFFER )
~~~~

Where CMK is the Compound MAC key derived above for this round, and
the definition of BUFFER is the same as with TEAPv1 (TBD).

## EAP Master Session Key Generation

TEAP authentication assures that the MSK and EMSK output from running
TEAP are combined result of all inner methods.  The resulting MSK and
ESMK are generated from the final inner method, via the following
derivation:

~~~
   MSK  = the first 64 octets of TLS-PRF(RoundSeed,
          "Session Key Generating Function")
   EMSK = the first 64 octets of TLS-PRF(RoundSeed,
          "Extended Session Key Generating Function")
~~~

The value for RoundSeed MUST use the PrevRoundSeed from the previous
round, and the MSK and the EMSK from the final inner message.

## Operation across Multiple Rounds

Unlike TEAPv1, every message for every round in TEAPv2 MUST contain a
Crypto-Binding TLV.  This cryptographic binding helps protect from
on-path attackers.

Any party which sends a message in TEAPv2 MUST include a
Crypto-Binding TLV.  Any party which receives a message in TEAPv2 MUST
verify that it contains a Crypto-Binding TLV

TBD: discuss why use of MSK only in TEAPv1 is likely to avoid
cryptographic binding?  The session_key_seed is taken from the
TLS-Exporter(), which binds it to the tunnel.  But subsequent
exchanges of MSK-only methods do not bind the results to the tunnel.

## TEAPv2 Message Format

The TEAPv2 message format is identical to that of (TBD), with only one
change: the Ver field is set to "2", to indicate that this is TEAPv2.

## TEAPv2 TLVs

The TEAPv2 TLV definitions are identical to that for TEAPv1, with only
the changes and additions noted below.

### Crypto-Binding TLV

The definition of the TEAPv2 Crypto-Binding TLV is the same as for
TEAPv1 (TBD), with the following changes:

* The Version field MUST set to two (2).

* The Received-Ver field MUST be set to two (2), to indicate TEAPv2.

* The Flags field MUST have value 2, to indicate that only the MSK
  Compound-MAC is present.

* the Nonce field is not used.  It SHOULD be set to zeros by the
  sender.  The receiver MUST ignore it.

* The ESMK Compound-MAC field is not used.  It SHOULD be set to zeros
  by the sender.  The receiver MUST ignore it.

* The MSK Compound-MAC field is calculated as described above in
  [](#computing-compound-mac).

Note that unlike TEAPv1, only one CMK is derived for each inner
message, which also means that only one Compound-MAC is derived.  This
Compound-MAC is placed into the MSK Compound-MAC field, and the EMSK
Compound-MAC field is not used.  The alternative would be to redefine
the entire contents of the Crypto-Binding TLV.  Re-using the existing
Crypto-Binding TLV format means that there are minimal changes
required to implementations, which is a more useful property than any
trivial optimization to save a few octets of data being exchanged.

### Pseudo-MSK-Contents TLV

The Pseudo-MSK-Contents TLV provides a mechanism for the sender to inform
the receiver as to which attribute or attributes were used to
calculate the pseudo MAC.

The Pseudo-MSK-Contents TLV MUST be included in any message where no
authentication is taking place.  The Pseudo-MSK-Contents TLV MUST be
included in any message where the inner authentication method does not
derive either an MSK or an EMSK.

The Pseudo-MSK-Contents TLV MUST NOT be included in any message where the
inner authentication method derives either an MSK or an EMSK.

~~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|M|R|         TLV Type          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Type Reference         | ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~

M

> 1 - Required TLV

R

> Reserved, set to zero (0)

TLV Type

> 20 - Pseudo-MSK-Contents

Length

> The Length field is two octets and contains the length of the TLV
> field in octets.  The Length MUST be at least two (2), and MUST a
> multiple of two (2).

Type Reference

> An array of one or more 2-octet values.  The values MUST be the TLV
> Type numbers of the TLVs which were used as input to the pseudo MAC
> calculation.

## Implicit Challenges

TBD EAP-MSCHAPv2

# Security Considerations

# IANA Considerations

TBD - assing new Pseduo-MSK-Contents TLV

--- back
