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

things


{mainmatter}


# Introduction

## Timeline

  * 2005: Theoretical 2^63 attack on SHA-1 by Wang Xiaoyun et al.

  * 2006: NIST starts to deprecate SHA-1

    https://csrc.nist.gov/News/2006/NIST-Comments-on-Cryptanalytic-Attacks-on-SHA-1

  * 2010: DNS root zone signed with RSASHA256

    https://www.root-dnssec.org/

  * 2011: NIST formally deprecates SHA-1 for digital signatures, and
    disallows it after 2013

    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-131a.pdf

  * 2013: IETF recommends RSASHA1 for use in DNSSEC [@!RFC6944]

  * 2014: CA/Browser forum sunsets SHA-1 in X.509 WebPKI certificates after 2015

    https://cabforum.org/2014/10/16/ballot-118-sha-1-sunset/

  * 2015: SHAppening free-start collision demonstrated in SHA-1

    https://sites.google.com/site/itstheshappening/

  * 2017: SHAttered classical collision demonstrated in SHA-1

    https://shattered.io/

  * 2019: IETF deprecates SHA-1 for use in DNSSEC [@!RFC8624]

  * 2020: SHAmbles chosen-prefix collision demonstrated in SHA-1

    https://sha-mbles.github.io/


## Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**,
**SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**,
and **OPTIONAL** in this document are to be interpreted as described in
[@!RFC2119].



# Other uses of SHA-1 in the DNS

## DS records

## NSEC3 records

## SSHFP records

## TSIG authentication


# IANA considerations


# Security considerations


{backmatter}


# Acknowledgments

Thanks to Viktor Dukhovni for helpful discussions about the
implications of the some of the details that went in to this post.
