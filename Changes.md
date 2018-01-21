
1.0.13 - 2018-01-19

- restore load_tls_ini to index.js

1.0.12 - 2018-01-19

- restore openssl-wrapper dependency (it's missing in Haraka's package.json)

1.0.11 - 2018-01-19

- get_public_ip: assign timer before calling connect #29
    - avoid race where timeout isn't cleared because stun connect errors immediately
- remove TLS functions that have been subsumed into Haraka/tls_socket: load_tls_ini, tls_ini_section_with_defaults, parse_x509_names, parse_x509_expire, parse_x509, load_tls_dir
    - remove openssl-wrapper dependency
- convert concatenated strings to template literals #28
- eslint updates #25, #27
- improved x509 parser #22

1.0.10 - 2017-07-27

- added vs-stun as optional dep (from Haraka) #21

1.0.9 - 2017-06-16

- lint fixes for compat with eslint 4  #18

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

