# CVE-2020-9273

These are the files I created during analysis and exploitaion of [CVE-2020-9273](https://nvd.nist.gov/vuln/detail/CVE-2020-9273) - a heap use-after-free in [ProFTPd](http://www.proftpd.org/).

Take a look at the exploit video [here](https://twitter.com/DUKPT_/status/1344481049934348288).

Description about the files in this repo:

**poc-not-really-v4.c** - an article and poc I wrote last year (oct/2020), read to understand the exploitation path;

**exploit_demo.c** - demo exploit released, with hardcoded addresses, dated from last year too;

**exploit_proftpd.c** - reliable exploit, for localhost testing, finished on 16/08/2021.

Please feel free to DM me if you have questions or comments.
