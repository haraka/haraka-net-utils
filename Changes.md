
#### N.N.N - YYYY-MM-DD


### [1.3.6] - 2022-06-01

#### Added

- 

#### Fixed

- 

#### Changed

- 
- release 1.3.5


#### 1.3.5 - 2022-05-27

- chore(ci): use shared GHA workflows
- style(es6): use dns.promises internally
- dep(async): replace async dependency with Promise.all
- doc(README): use code fences around examples (vs indention)


#### 1.3.4 - 2022-01-05

- promisify get_ips_by_host (backwards compatible)


#### 1.3.3 - 2020-01-05

- refactored is_local_host function to return a promise instead of using a callback #65


#### 1.3.2 - 2021-12-20

- add is_local_host function #63


#### 1.3.1 - 2021-10-13

- get_mx: wrap dns.resolveMx in a try haraka/Haraka#2985
- add .release scripts
- add GH workflow, publish release to NPM upon merge to master


#### 1.3.0 - 2021-01-23

- Support passing an array to ip_in_list #60


#### 1.2.4 - 2021-01-14

- add "any" IP to is_local_ip
- add TEST-NET-[1-3] to is_private_ip


#### 1.2.3 - 2020-12-19

- fix: restore the tests wrapping the resolveMX iterable


#### 1.2.2 - 2020-12-15

- get_mx: do not include implicit MX


#### 1.2.1 - 2020-11-17

- bump ipaddr.js to 2.0.0 #56


#### 1.2.0 - 2020-06-23

- added get_mx
- remove deprecated load_tls_ini
- remove deprecated tls_ini_section_with_defaults


#### 1.1.5 - 2020-04-11

- ipv6_bogus: handle parsing broken ipv6 addresses #49
- update async to version 3.0.1 #43


#### 1.1.4 - 2019-04-04

- stop is_private_ip from checking if the IP is bound to a local network interface


#### 1.1.3 - 2019-03-01

- is_local_ip checks local network interfaces too


#### 1.1.2 - 2018-11-03

- add is_local_ip


#### 1.1.1 - 2018-07-19

- ip_in_list doesn't throw on empty list


#### 1.1.0 - 2018-04-11

- add get_primary_host_name haraka/Haraka#2380


#### 1.0.14 - 2018-01-25

- restore tls_ini_section_with_defaults function (deprecated since Haraka 2.0.17)


#### 1.0.13 - 2018-01-19

- get_public_ip: assign timer before calling connect #29
    - avoid race where timeout isn't cleared because stun connect errors immediately
- remove TLS functions that have been subsumed into Haraka/tls_socket: tls_ini_section_with_defaults, parse_x509_names, parse_x509_expire, parse_x509, load_tls_dir
- convert concatenated strings to template literals #28
- eslint updates #25, #27
- improved x509 parser #22


#### 1.0.10 - 2017-07-27

- added vs-stun as optional dep (from Haraka) #21


#### 1.0.9 - 2017-06-16

- lint fixes for compat with eslint 4  #18


#### 1.0.8 - 2017-03-08

- skip loading expired x509 (TLS) certs
- make TLS cert dir configurable
- rename certs -> cert (be consistent with haraka/plugins/tls)
- store cert/key as buffers (was strings)


#### 1.0.7 - 2017-03-08

- handle undefined tls.ini section


#### 1.0.6 - 2017-03-04

- add tls_ini_section_with_defaults()
- add load_tls_dir()
- add parse_x509_names()


#### 1.0.5 - 2016-11-20

* add enableSNI TLS option


#### 1.0.4 - 2016-10-25

* initialize TLS opts in (section != main) as booleans


#### 1.0.3 - 2016-10-25

* added tls.ini loading
[1.3.6]: https://github.com/haraka/haraka-net-utils/releases/tag/1.3.6
