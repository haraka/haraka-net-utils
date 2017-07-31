
1.0.10 - 2017-07-27

- added vs-stun as optional dep (from Haraka)

1.0.9 - 2017-06-16

- lint fixes for compat with eslint 4

1.0.8 - 2017-03-08

- skip loading expired x509 (TLS) certs
- make TLS cert dir configurable
- rename certs -> cert (be consistent with haraka/plugins/tls)
- store cert/key as buffers (was strings)

1.0.7 - 2017-03-08

- handle undefined tls.ini section

1.0.6 - 2017-03-04

- add tls_ini_section_with_defaults()
- add load_tls_dir()
- add parse_x509_names()

1.0.5 - 2016-11-20

* add enableSNI TLS option

1.0.4 - 2016-10-25

* initialize TLS opts in (section != main) as booleans

1.0.3 - 2016-10-25

* added tls.ini loading

