# Overview
This repository is a set of integrations to allow direct DUO MFA integration with freeradius using either Python 3 or Perl.


## freeradius
Functionally, the python and perl versions are exactly the same.  I originally used the perl interface due to perl support in freeradius being more established and stable versus the python support.  When I wrote this in 2019/2020, Python 3 support was just emerging.


### dictionary
Both the python and perl integration requires custom dictionary entries for data stored from the DUO API

```
ATTRIBUTE       User-Password-Otp       3000    string
ATTRIBUTE       Duo-User-Devices        3010    string array
ATTRIBUTE       Duo-2fa-Bypass          3020    string
```

### password_otp_split policy
A policy will need to be installed to split the password in the case of using [Append Mode](https://guide.duo.com/append-mode).  The password split policy supports OTP codes, Yubikeys, and alternate device specifications.


## Python 3
Recommend creating a virtualenv to install the `duo-client` module.  The sys.path needs to be updated in the python module for the virtualenv.


## Perl
The only special handling for perl is the default JSON parsing module for perl `JSON::XS` is not thread safe.  The perl interpreter in freeradius runs as a thread.  My recollection is if you do not change the default JSON parser, the authentication would always **succeed** and never fail.

The default JSON parser can be changed by setting the `PERL_JSON_BACKEND` environment variable for the freeradius service.  On Debian distributions, this environment variables may be set in `/etc/defaults/freeradius`

Thread safe JSON parsers:
* Cpanel::JSON::XS
* JSON::PP


### Perl modules
```
sudo apt-get install \
  libdigest-hmac-perl \
  libjson-perl \
  libcpanel-json-xs-perl \
  libjson-pp-perl \
  libwww-perl \
  libhttp-message-perl \
  liblwp-protocol-https-perl
```


## Slack
In both the python and perl scripts, there are hooks to allow slack webhook notifications when authentications occur.  These are currently commented out by default, but the webhook notifications occur in sub-threads in case the webhook fails, it will not interrupt the authentication.

This is a standard HTTP call and just about any webhook could be implemented if you know how to create the raw http communication.


## Debugging
If you have problems, you can shutdown the freeradius service and run it in single process mode with debugging using `freeradius -X`.

