Hardening DNSSEC against hash collisions
========================================

See the introduction in [the source text of this draft](draft.md)
to find out what this is about.

# Contributing

This repository relates to activities in the Internet Engineering Task
Force (IETF). See the [LICENSE](LICENSE.md) file for the legal boilerplate.

Discussion of this work occurs on the
[dnsop working group mailing list](https://mailarchive.ietf.org/arch/browse/dnsop/)
([subscribe](https://www.ietf.org/mailman/listinfo/dnsop)).
In addition to contributions in GitHub, you are encouraged to
participate in discussions on the mailing list especially for
substantive discussion of technical issues.

You might also like to familiarize yourself with other
[dnsop working group documents](https://datatracker.ietf.org/wg/dnsop/documents/).

# Building

Run `make` to rebuild the generated files from the `.md` source.

The markdown source is converted to RFC XML format using `mmark`

  * https://github.com/mmarkdown/mmark

Plain text and HTML versions are generated from the XML using `xml2rfc`

  * https://xml2rfc.tools.ietf.org/

The canonical version of this repository is

  * https://github.com/fanf/draft-dnsop-sha-ll-not
