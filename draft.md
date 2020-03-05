%%%
title           = "Hardening DNSSEC against collision weaknesses in SHA-1 and other cryptographic hash algorithms"
abbrev          = "DNSSEC vs collision attacks"
workgroup       = "DNS Operations"
area            = "Operations and Management"
submissiontype  = "IETF"
ipr             = "trust200902"
date            = 2020-02-27T19:13:12Z
keyword         = [
    "DNS",
    "SHA-1",
    "RRSIG",
]
updates         = [ 8624 ]

[seriesInfo]
name            = "Internet-Draft"
value           = "draft-fanf-dnsop-sha-mbles"
status          = "standard"

[[author]]
initials        = "T."
surname         = "Finch"
fullname        = "Tony Finch"
organization    = "University of Cambridge"
 [author.address]
 email          = "dot@dotat.at"
  [author.address.postal]
  streets       = [
    "University Information Services",
    "Roger Needham Building",
    "7 JJ Thomson Avenue",
  ]
  city          = "Cambridge"
  country       = "England"
  code          = "CB3 0RB"

%%%

.# Abstract

DNSSEC deployments have often used the SHA-1 cryptographic hash
algorithm to provide authentication of DNS data. This document
explains why SHA-1 is no longer secure for this purpose, and
deprecates its use in DNSSEC signatures. This document updates
RFC 8624.


{mainmatter}


# Introduction

Since 2005, SHA-1 has been known to be much weaker than it was
designed to be. Over the last 5 years there has been a series of
increasingly powerful demonstrations that SHA-1's weaknesses can be
exploited in practice. In January 2020, Gaëtan Leurent and Thomas
Peyrin announced a chosen-prefix collision for SHA-1 [SHA-mbles]. This
was the first practical break of SHA-1 as used in cryptographic
signatures.

DNSSEC uses cryptographic signatures to authenticate DNS data. Its
signature algorithms [@?DNSKEY-IANA] include RSASHA1 (5) and
RSASHA1-NSEC3-SHA1 (7) which are vulnerable to chosen-prefix
collisions in SHA-1, as described in (#collide). This document
deprecates these vulnerable algorithms ((#deprecate)).

SHA-1 has been deprecated in other situations for several years (see
(#timeline)). This document's timetable for deprecating SHA-1 in
DNSSEC ((#deprecate)) is based on those examples, adapted for the
particulars of the DNS. (#seccons) discusses the trade-offs between
speed and security.

A collision attack can be used against DNSSEC in a number of ways,
some of which are explored in (#attack). Certain weaknesses in the way
DNSSEC is sometimes deployed can make collision attacks easier to
carry out, or make their consequences more severe. Although the only
sure way to protect against collision attacks is to use a secure
algorithm ((#deprecate)), (#harden) and (#attack) outline some partial
mitigations.

The DNS uses SHA-1 for a number of other less vulnerable purposes, as
outlined in section (#otherr).

## Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**,
**SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**,
and **OPTIONAL** in this document are to be interpreted as described in
[@!RFC2119].


# Deprecating SHA-1 in DNSSEC {#deprecate}

The following table lists the implementation recommendations for
DNSKEY algorithms [@?DNSKEY-IANA]. The change from [@?RFC8624]
section 3.1 is to deprecate algorithms 5 and 7.

No. | Mnemonic           | DNSSEC Signing  | DNSSEC Validation
----|--------------------|-----------------|------------------
1   | RSAMD5             | MUST NOT        | MUST NOT
3   | DSA                | MUST NOT        | MUST NOT
5   | RSASHA1            | MUST NOT        | MUST NOT after 2021
6   | DSA-NSEC3-SHA1     | MUST NOT        | MUST NOT
7   | RSASHA1-NSEC3-SHA1 | MUST NOT        | MUST NOT after 2021
8   | RSASHA256          | MUST            | MUST
10  | RSASHA512          | NOT RECOMMENDED | MUST
12  | ECC-GOST           | MUST NOT        | MAY
13  | ECDSAP256SHA256    | MUST            | MUST
14  | ECDSAP384SHA384    | MAY             | RECOMMENDED
15  | ED25519            | RECOMMENDED     | RECOMMENDED
16  | ED448              | MAY             | RECOMMENDED

The following subsections have recommended timelines for deprecating
algorithms 5 and 7 in specific situations.


## DNSSEC signing software

DNSSEC key management and zone signing software MUST remove support
for algorithms 5 and 7 in their next feature release.


## DNS hosting services

Authoritative DNS hosting services that include DNSSEC signing as part
of the service SHOULD NOT generate a new key with algorithms 5 or 7
for a zone that does not already have a key with the same algorithm.
They MUST NOT do so after the end of 2020.

Zones signed with algorithms 5 or 7 SHOULD be rolled over to a
mandatory or recommended algorithm as soon as possible. The rollovers
MUST be complete before the end of 2021.


## DNSSEC validating software

Validating resolvers SHOULD have a build-time or run-time option to
disable selected DNSKEY algorithms, that is, to treat them as unknown
or insecure.

Algorithms 5 and 7 MUST be disabled in 2022 at the latest. If SHA-1
becomes significantly weaker before then, Algorithms 5 and 7 MUST be
disabled in a security patch release.


## DNS resolver services

Validating resolvers MUST treat algorithms 5 and 7 as unknown or
insecure after the start of 2022, or earlier if SHA-1 becomes
significantly weaker before then.


# Collision attacks against DNSSEC {#collide}


# Collision attacks and RRSIG records {#harden}


# Collision attacks and other DNS record types {#attack}


# Other uses of SHA-1 in the DNS {#otherr}

## DS and CDS records

A DS or CDS record securely identifies a DNSKEY record using a
cryptographic digest ([@!RFC4034] section 5). One of the digest types
is SHA-1. It is deprecated by [@?RFC8624].

For this purpose, the digest needs preimage security, which SHA-1
still has, and collision attacks do not affect it.

## NSEC3 records

NSEC3 is an alternative mechanism for authenticated denial of
existence in DNSSEC. It is based on SHA-1 hashes of domain names. The
NSEC3 specification [@?RFC5155] discusses collisions in some detail.

NSEC3 can be attacked with an identical-prefix collision, which is
simpler than the chosen-prefix collisions that are the main subject
of this document. The best collision known at the time of writing
[@?SHAttered] uses two SHA-1 input blocks (128 bytes) so a collision
could in principle be made to fit into a domain name for an attack
on NSEC3. However it will be difficult to make the colliding domain
names conform to host name syntax, and the attack will be futile
because the signer can defeat it by changing its NSEC3 salt
([@?RFC5155] section C.2.1).

## SSHFP records

An SSHFP record securely identifies an SSH server public key using a
cryptographic digest [@?RFC4255]. Although SSHFP SHA-1 digests have
not yet been deprecated, SHA-256 is preferred [@?RFC6594].

For SSHFP records the digest needs preimage security, which SHA-1
still has, and collision attacks do not affect it.

## TSIG authentication

TSIG is a DNS extension for secret-key transaction authentication
[@?I-D.ietf-dnsop-rfc2845bis]. Its `hmac-sha1` algorithm is
deprecated. Collision attacks do not affect HMAC SHA-1.


# Security considerations {#seccons}

We find ourselves in an awkward and embarrassing situation. As
(#timeline) shows, there has been plenty of warning about the
weakness of SHA-1. Other parts of the industry started making
efforts to deprecate it years ago. But DNSSEC has been complacent.

At the time of writing, there are 1516 top-level domains, of which
1102 use secure DNSSEC algorithms, 274 use algorithms 5 or 7 (RSA
SHA-1), and 140 are insecure. In the reverse DNS, 3 RIRs use secure
DNSSEC algorithms, 2 RIRs use algorithm 5, and many of the non-RIR
legacy delegations are insecure.

## Staying secure

There are still many domains that depend on SHA-1 to secure
applications that use DNSSEC, such as issuing TLS certificates
[@?RFC6844] [@?RFC8555], sending inter-domain email [@?RFC7672],
and authenticating SSH servers [@?RFC4255].

Some applications use the "authenticated data" (AD bit) signal from
DNSSEC to make security decisions, and will fail if it unexpectedly
switches off. Other applications use DNSSEC passively and will
silently go insecure. In either case we would prefer them to
continue working as if secure, as long as SHA-1 is still
significantly better than insecure DNS.

## When to declare SHA-1 insecure

At the time of writing, a SHA-1 chosen-prefix collision costs less
than US$100,000 in computer time, takes about a month, and requires
the attention of expert cryptanalysts. Attacks seem to be getting
better by a factor of 3 or 4 per year.

There is not much time before collisions become affordable, and
possible for non-experts to calculate. (#deprecate) hopes this will
not happen within the next 2 years.

This 2 year guess is likely to be too optimistic, so DNSSEC
validators need to be prepared to disable support for SHA-1 by
configuration change or security patch as soon as a significantly
improved attack on SHA-1 is announced.

## Avoiding unwanted insecurity

The reason for not deprecating SHA-1 immediately is to allow time to
perform algorithm rollovers, so that zones will continue to be secure.

Abruptly forcing SHA-1 zones to be treated as insecure may encourage
their operators to leave them insecure, instead of encouraging them
to upgrade to a secure algorithm.


# IANA considerations

This document has no IANA actions.


{backmatter}


# Acknowledgments

Thanks to Viktor Dukhovni for helpful discussions about the
implications of the SHA-1 chosen-prefix collision.


# Timeline

  * 2005: Theoretical 2^63 attack on SHA-1 [@?Wang2005] [@?Cochran2007]

<reference anchor='Wang2005' target='https://link.springer.com/chapter/10.1007/11535218_2'>
  <front>
    <title>Finding Collisions in the Full SHA-1</title>
	<author initials='X.' surname='Wang' fullname='Xiaoyun Wang'/>
	<author initials='Y.' surname='Yin' fullname='Yiqun Lisa Yin'/>
	<author initials='H.' surname='Yu' fullname='Hongbo Yu'/>
    <date year='2005'/>
  </front>
</reference>

<reference anchor='Cochran2007' target='https://eprint.iacr.org/2007/474'>
  <front>
    <title>Notes on the Wang et al. 2^63 SHA-1 Differential Path</title>
	<author initials='M.' surname='Cochran' fullname='Martin Cochran'/>
	<date year='2007'/>
  </front>
</reference>

  * 2006: NIST starts to deprecate SHA-1 [@?NIST2006]

<reference anchor='NIST2006' target='https://csrc.nist.gov/News/2006/NIST-Comments-on-Cryptanalytic-Attacks-on-SHA-1'>
  <front>
    <title>NIST Comments on Cryptanalytic Attacks on SHA-1</title>
	<author><organization abbrev='NIST'>
	  National Institute of Standards and Technology
	</organization></author>
	<date year='2006'/>
  </front>
</reference>

  * 2010: DNS root zone signed with RSASHA256 [@?ROOT-DNSSEC]

<reference anchor='ROOT-DNSSEC' target='https://www.root-dnssec.org/'>
  <front>
    <title>Information about DNSSEC for the Root Zone</title>
	<author><organization abbrev="ICANN">
	  Internet Corporation For Assigned Names and Numbers
	</organization></author>
	<author><organization>VeriSign, Inc.</organization></author>
	<date year='2010'/>
  </front>
</reference>

  * 2011: NIST formally deprecates SHA-1 for digital signatures, and
    disallows it after 2013 [@?NIST-SP800-131A] (section 3)

<reference anchor='NIST-SP800-131A' target='https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-131a.pdf'>
  <front>
    <title>Recommendation for Transitioning the Use of CryptographicAlgorithms and Key Lengths</title>
	<author><organization abbrev='NIST'>
	  National Institute of Standards and Technology
	</organization></author>
	<date month='January' year='2011'/>
  </front>
</reference>

  * 2013: IETF recommends RSASHA1 for use in DNSSEC [@?RFC6944]

  * 2014: CA/Browser forum sunsets SHA-1 in X.509 WebPKI certificates
    after 2015 [@?CABforum2014]

<reference anchor='CABforum2014' target='https://cabforum.org/2014/10/16/ballot-118-sha-1-sunset/'>
  <front>
    <title>Ballot 118 - SHA-1 Sunset</title>
	<author><organization>CA/Browser Forum</organization></author>
	<date month='October' year='2014'/>
  </front>
</reference>

  * 2015: Free-start collision demonstrated in SHA-1 [@?SHAppening]

<reference anchor='SHAppening' target='https://sites.google.com/site/itstheshappening/'>
  <front>
    <title>Freestart collision for full SHA-1</title>
	<author initials='M.' surname='Stevens' fullname='Marc Stevens'/>
	<author initials='P.' surname='Karpman' fullname='Pierre Karpman'/>
	<author initials='T.' surname='Peyrin' fullname='Thomas Peyrin'/>
	<date month='October' year='2015'/>
  </front>
</reference>

  * 2017: Identical-prefix collision demonstrated in SHA-1 [@?SHAttered]

<reference anchor='SHAttered' target='https://shattered.io/'>
  <front>
    <title>The first collision for full SHA-1</title>
	<author initials='M.' surname='Stevens' fullname='Marc Stevens'/>
	<author initials='E.' surname='Bursztein' fullname='Elie Bursztein'/>
	<author initials='P.' surname='Karpman' fullname='Pierre Karpman'/>
	<author initials='A.' surname='Albertini' fullname='Ange Albertini'/>
	<author initials='Y.' surname='Markov' fullname='Yarik Markov'/>
	<date month='February' year='2017'/>
  </front>
</reference>

  * 2019: IETF partially deprecates SHA-1 for use in DNSSEC [@!RFC8624]

  * 2020: Chosen-prefix collision demonstrated in SHA-1 [@?SHA-mbles]

<reference anchor='SHA-mbles' target='https://sha-mbles.github.io/'>
  <front>
    <title>
	  SHA-1 is a Shambles:
	  First Chosen-Prefix Collision on SHA-1
	  and Application to the PGP Web of Trust
	</title>
	<author initials='G.' surname='Leurent' fullname='Gaëtan Leurent'/>
	<author initials='T.' surname='Peyrin' fullname='Thomas Peyrin'/>
	<date month='January' year='2020'/>
  </front>
</reference>


<reference anchor='DNSKEY-IANA' target='http://www.iana.org/assignments/dns-sec-alg-numbers'>
  <front>
    <title>Domain Name System Security (DNSSEC) Algorithm Numbers</title>
	<author><organization>IANA</organization></author>
    <date year='2017'/>
  </front>
</reference>

<!--
<reference anchor='' target=''>
  <front>
    <title></title>
	<author initials='.' surname='' fullname=''/>
	<author><organization>IANA</organization></author>
	<date year=''/>
  </front>
</reference>
-->
