%%%
title           = "Hardening DNSSEC against collision weaknesses in SHA-1 and other cryptographic hash algorithms"
abbrev          = "DNSSEC vs collision attacks"
workgroup       = "DNS Operations"
area            = "Operations and Management"
submissiontype  = "IETF"
ipr             = "trust200902"
date            = 2020-03-05T18:55:00Z
keyword         = [
    "DNS",
    "SHA-1",
    "RRSIG",
]
updates         = [ 8624 ]

[seriesInfo]
name            = "Internet-Draft"
value           = "draft-fanf-dnsop-sha-ll-not"
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
speedy deprecation and security.

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
mandatory algorithm (13 or 8) as soon as possible. The rollovers
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

This section explains how collisions in cryptographic functions
(such as SHA-1) can be used to break DNSSEC data authentication.
(#attack) has some more specific examples of how this break can be
used to mount attacks.

## Chosen-prefix collisions

With hash functions like SHA-1, a chosen-prefix collision attack
uses two messages that have a structure like this:

```
            +----------+-----------+--------+
message-1:  | prefix-1 | collide-1 | suffix |
            +----------+-----------+--------+

            +----------+-----------+--------+
message-2:  | prefix-2 | collide-2 | suffix |
            +----------+-----------+--------+
```

The two prefixes are entirely under the attacker's control.

The collision blocks are calculated to make the hashes collide. They
look like binary junk and cannot be made to conform to any
particular syntax. The collision blocks are 588 bytes long in the
best attack on SHA-1 at the time of writing [@?SHA-mbles].

The messages may need a suffix so that they are syntactically valid,
but this must be the same in both messages.

## Collision attacks and signatures

A signature algorithm like RSASHA1 takes a cryptographic hash of the
message (using SHA-1 in this case) and uses an asymmetric algorithm
(RSA in this case) to turn the hash into a signature.

If the hash function is vulnerable, like SHA-1, then an attacker can:

  * construct two prefixes, one innocuous and one malicious;

  * calculate collision blocks so the two messages have the same hash;

  * submit the innocuous message to be signed by some authority;

  * copy the signature from the innocious message to the malicious
    message;

  * use the signed malicious message to perform attacks that would
    not be possible without it.

The copied signature works on both the innocuous and malicious
messages because their hashes match.

It is usually less easy than this, because in most protocols part of
the innocuous message is chosen by the signer, so the attacker needs
to predict how the signer will work.

## Breaking DNSSEC

To use a collision attack against DNSSEC, the innoccuous and
malicious messages are DNS RRsets.

DNSSEC provides strong authentication for DNS data. Within the DNS,
it prevents spoofing attacks and cache poisoning attacks. For
applications that use the DNS, DNSSEC can provide strong
authentication for application identifiers, such as a host name and
associated public key or challenge/response. Breaking DNSSEC means
subverting this authentication.

If an attacker has even very limited access to update a DNS zone
that uses SHA-1 (algorithm 5 or 7), the attacker can use a collision
attack to gain control over other names in the same zone.

Our attacker is able to update the DNS for certain innoccuous
records. The zone owner signs the updated innoccuous records and
publishes the new records and RRSIG in the zone. The attacker can
then make a DNS query for the updated records, and copy the
signature field from the innoccuous RRSIG into the signature field
of the attacker's malicious RRSIG. The attacker can use the signed
malicious RRset as part of a DNS spoofing or cache poisoning attack.
(#attack) has some examples.

## Collision attacks and RRSIG records

When the attacker calculates the collision blocks, there is a bit
more to the innoccuous and malicious messages than just the RRsets.
They need to be in the format used for constructing RRSIG records
specified in [@!RFC4034] section 3.1.8.1 and sketched in the diagram
below:

```
+------------------------------------+
| RRSIG RDATA                        |
+------------------------------------+
| NAME TYPE CLASS TTL RDLENGTH RDATA |
+------------------------------------+
| ... more records ...               |
+------------------------------------+
| NAME TYPE CLASS TTL RDLENGTH (     |
|                 collision blocks ) |
+------------------------------------+
```

The RRSIG RDATA is controlled by the signer, and must be predicted
by the attacker. (#harden) discusses how easy it is to predict the
RRSIG RDATA fields.

The DNS records are under the attacker's control, with some
limitations:

  * In the innoccuous records, the NAME and TYPE identify an RRset
    that the attacker can update.

  * In the malicious records, the NAME must be in a zone signed by
    the same key as the innoccuous records.

  * The innoccuous and malicious TYPEs do not need to be the same,
    but they must both have RDATA fields that can accommodate the
    collision blocks.

  * The attacker needs to ensure the records containg the collision
    blocks come last when the RRsets are sorted into canonical
    order.

  * The innoccuous and malicious records do not have to be aligned
    with each other, but they need to have the same total length.


# Hardening RRSIG records {#harden}

To perform a collision attack against DNSSEC, the attacker needs to
know the RRSIG RDATA fields that the zone owner will use when
signing the attacker's innoccuous records.

The RRSIG RDATA fields are specified in [@!RFC4034] section 3.1.
They are:

  * Type covered: same as the TYPE of the innoccuous RRset.

  * Algorithm: same as the algorithm of the zone's DNSKEY records,
    which for a vulnerable zone will be 5 or 7.

  * Labels: derived from the NAME of the innoccuous RRset.

  * Original TTL: same as the TTL of the innoccuous RRset.

  * Signature expiration: a time set by the signer.

  * Signature inception: a time set by the signer.

  * Key tag: obtained from one of the zone's DNSKEY records.

  * Signer's name: the name of the zone's DNSKEY records.

We can see that all of these fields are known to the attacker, apart
from the inception and expiration times.

## Predicting inception and expiration times

There are a number of common ways for DNSSEC signers to set
signature inception and expiration times:

  * The times are known offsets from the moment a DNS update is
    processed.

  * The update time is rounded to a multiple of (for example) 24
    hours and the signature times are known offsets from that.

  * The zone is signed on a known schedule and the times are derived
    from that schedule.

So in many cases an attacker can predict all the RRSIG RDATA fields
with little difficulty.

## Unpredictable X.509 certificates

(A brief diversion to provide some rationale for the next
sub-section.)

In 2008 a chosen-prefix collision attack against MD5 was used to
obtain an illegitimate CA certificate signed by a commercial CA
[ROGUE-CA]. A key part of this attack was to predict the serial
number and validity period assigned by the commercial CA to the
innocuous certificate so that its MD5 hash would collide with the
malicious rogue CA certificate.

Following this attack, certificate authorities started using random
serial numbers instead of sequential numbers. In 2016 the CA/Browser
forum baseline requirements were amended to increase the amount of
randomness required from 20 bits to 64 bits [CABforum2016]. This
extra hardening was in addition to deprecating SHA-1 [CABforum2014].

## Less predictable RRSIG records

In addition to upgrading to a secure algorithm ((#deprecate)),
DNSSEC signers can provide extra protection against possible
collision attacks by adding entropy to make RRSIG inception and
expiration times less predictable.

The inception time SHOULD include at least 12 bits of output from a
CSPRNG. (2^12 seconds is slightly more than an hour.) For example,
set the inception time to the signing time minus an hour minus the
entropy.

The expiration time SHOULD include output from a CSPRNG equivalent
to about 25% of the nominal validity period. For instance, 19 bits
(6 days) if the validity period is 1 month, or 17 bits (1.5 days) if
the validity period is 1 week. For example, set the expiration time
to the signing time plus 75% of the validity period plus the
entropy.


# Collision attacks and other DNS record types {#attack}

This section discusses how a SHA-1 collision attack can be used with
various DNS record types. For an RRtype to be suitable it needs to
have a large RDATA with basically no internal structure, to
accommodate the collision blocks, which are 588 bytes long in the
best attack on SHA-1 at the time of writing [@?SHA-mbles].

There are a number of weaknesses that make a collision attack easier
to carry out, or which make the consequences of an attack more
severe. This section describes some mitigations for these
weaknesses, but note that these mitigations do not prevent collision
attacks. The main defence is to upgrade zones to a secure algorithm
((#deprecate)) and in many cases that will be easier than the
additional mitigations outlined below.

## TXT records

TXT records are an attractive vehicle for a collision attack.

Access to update TXT records might be granted to support things like
ACME dns-01 challenges [@?RFC8555], so they can be useful as an
attacker's innoccuous records.

As the target of an attacker's malicious records, TXT records have
several interesting functions that might be useful to an attacker,
including ACME [@?RFC8555], DKIM [@?RFC6376], SPF [@?RFC7208],
authorization to provision cloud services, etc.

### Syntax of TXT records

A TXT record's RDATA contains a sequence of strings, each of which
is a length octet followed by up to 255 octets of data. A single
string is too small to accommodate SHA-1 collision blocks.

An attacker can cope with this difficulty by not worrying about how
the string lengths end up inside a collision block. At the end of
the block there will be some unpredictable length of string that
needs to be filled; the attacker can append 255 zero bytes, which
will fill the remainder of the unknown string. The excess zero bytes
will parse as a sequence of zero-length strings. Although the
unfilled string lengths may be different in the inoccuous and
malicious records, they are both fixed by an identical suffix of 255
zeroes.

### Mitigating TXT record attacks

Some attacks might be prevented by imposing stricter requirements on
TXT records, since most practical uses do not put un-encoded binary
data in TXT records.

An authoritative server MAY reject TXT records in DNS UPDATEs and
zone files if the strings contain ASCII control characters or
invalid UTF-8. This strict checking SHOULD be configurable so that
zone owners can use unrestricted binary in TXT records if they wish.

## CAA records

An attacker might want to spoof certificate authority authorization
records [@?RFC6844] in order to obtain an illegitimate X.509
certificate.

A CAA record contains tag and value strings. The length of the value
is unrestricted, which makes it easy to accommodate collision blocks.

To mitigate collision attacks on CAA records, the specifications for
CAA record syntax and how CAA records are processed by certificate
authorities could be tightened up to reject a CAA RRset unless it is
all printable ASCII.

## SSHFP records

An SSHFP record contains a fingerprint of a server public key
[@?RFC4255]. They are attractive as the target of a spoofing attack.

Access to update SSHFP records might be granted so that servers can
register themselves in the DNS, so SSHFP records can be useful as an
attacker's innoccuous records.

The length of an SSHFP record is implied by its fingerprint type
field, but they can be used in collision attacks if the length is
not strictly checked, or if unknown fingerprint types are allowed.

Authoritative DNS servers MAY reject SSHFP records with unknown
fingerprint types or mismatched lengths in DNS UPDATEs and zone
files. SSH clients MAY reject an entire SSHFP RRset if any record
has a fingerprint longer than 64 bytes. (Assuming that fingerprints
longer than 512 bits do not make sense.)

## DNSKEY records

## DS records


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

<reference anchor='ROGUE-CA' target='https://www.win.tue.nl/hashclash/rogue-ca/'>
  <front>
    <title>Creating a rogue CA certificate</title>
	<author initials='A.' surname='Sotirov' fullname='Alexander Sotirov'/>
	<author initials='M.' surname='Stevens' fullname='Marc Stevens'/>
	<author initials='J.' surname='Appelbaum' fullname='Jacob Appelbaum'/>
	<author initials='A.' surname='Lenstra' fullname='Arjen Lenstra'/>
	<author initials='D.' surname='Molnar' fullname='David Molnar'/>
	<author initials='D.' surname='Osvik' fullname='Dag Arne Osvik'/>
	<author initials='B.' surname='de Weger' fullname='Benne de Weger'/>
	<date month='December' year='2008'/>
  </front>
</reference>

<reference anchor='CABforum2016' target='https://cabforum.org/2016/03/31/ballot-164/'>
  <front>
    <title>Ballot 164 - Certificate Serial Number Entropy</title>
	<author><organization>CA/Browser Forum</organization></author>
	<date month='September' year='2016'/>
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
