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
Peyrin announced a chosen-prefix collision for SHA-1 [SHA-MBLES]. This
was the first practical break of SHA-1 as used in cryptographic
signatures.

DNSSEC uses cryptographic signatures to authenticate DNS data. Its
signature algorithms include RSASHA1 (5) and RSASHA1-NSEC3-SHA1 (7)
which are vulnerable to chosen-prefix collisions in SHA-1, as
described in section (#collide). This document deprecates these
vulnerable algorithms (#deprecate).

SHA-1 has been deprecated in other situations for several years (see
(#timeline)). This document's timetable for deprecating SHA-1 in
DNSSEC is based on those examples, adapted for the particulars of the
DNS. Section (#seccons) discusses the trade-offs between speed and
security.

As 

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

## DS records

## NSEC3 records

## SSHFP records

## TSIG authentication


# Security considerations {#seccons}


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

  * 2017: Classical collision demonstrated in SHA-1 [@?SHAttered]

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
