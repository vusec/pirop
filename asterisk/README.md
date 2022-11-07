# Testing

```
$ mkdir -p ~/asterisk/testsuite
$ cd ~/asterisk/testsuite
$ git clone https://gerrit.asterisk.org/testsuite
```

https://wiki.asterisk.org/wiki/display/AST/Installing+the+Asterisk+Test+Suite

# Deps 12.04 LTS:
```
$ sudo yum install libtiff4 libtiff4-dev
```

## Spandsp:
```
$ wget http://soft-switch.org/downloads/spandsp/spandsp-0.0.6.tar.gz
$ tar -xf spandsp-0.0.6.tar.gz
$ cd spandsp-0.0.6.tar.gz
$ ./configure
$ make
$ sudo make install
```

## SRTP
```
$ wget http://srtp.sourceforge.net/srtp-1.4.2.tgz
$ tar xvf srtp-1.4.2.tgz
$ cd srtp
$ ./configure CFLAGS=-fPIC --prefix=/usr
$ make
$ make runtest
$ sudo make install
```

## Test Suite pre-requisites

### 3rd party libs
```
$ sudo apt-get install liblua5.1-0-dev 
$ sudo apt-get install lua5.1
$ sudo apt-get install python-twisted
$ sudo apt-get install libpcap-dev
$ sudo apt-get install python-yaml
$ sudo apt-get install python-dev
```

python-construct not available in 12.04. So we install it manually:
```
$ wget https://codeload.github.com/construct/construct/tar.gz/v2.5.1 -O construct-2.5.1.tar.gz
$ tar -xf construct-2.5.1.tar.gz
$ cd consruct-2.5.1
$ sudo python setup.py install
```
https://installion.co.uk/ubuntu/yakkety/universe/p/python-construct/install/index.html

### asttest

```
$ # in testsuite
$ cd asttest
$ make
$ sudo make install
$ asttest # test if command works
```

### StarPY

```
$ # in testsuite
$ cd addons
$ make update
$ cd starpy
$ sudo python setup.py install
```

### SIPp

```
$ # in testsuite
$ mkdir sipp
$ cd sipp
$ wget https://github.com/SIPp/sipp/archive/v3.4.1.tar.gz
$ tar -zxvf v3.4.1.tar.gz
$ cd sipp-3.4.1
$ sudo apt-get install libncurses5 libncurses5-dev
$ ./configure --with-pcap --with-openssl
$ sudo make install
$ sipp -v # test if command works
```

### PJSUA

DEP:
```
$ sudo apt-get install libasound2-dev libasound2
```

Installation:
```
$ # in testsuite
$ svn co http://svn.pjsip.org/repos/pjproject/trunk pjproject
$ cd pjproject
```

edits:
```
$ vim third_party/yuv/source/row_gcc.cc
$ #add () around [kShuf..] on lines: 1562, 1570, 1572, 1578, 1580
$ #change "m" to "r" on lines: 1888, 1912, 1913, 1937, 1938
$ vim third_party/yuv/include/libyuv/row.h
$ # change line 400: "typedef int16 __attribute__((vector_size(32))) lvec16;"
$ # to: "typedef int16 lvec16[32];"
$ # change line 402: "typedef int8 __attribute__((vector_size(32))) lvec8;"
$ # to: "typedef int8 lvec8[32];"
```

```
$ ./configure CFLAGS=-fPIC LDFLAGS=-lasound
$ cp pjlib/include/pj/config_site_sample.h pjlib/include/pj/config_site.h
$ vim pjlib/include/pj/config_site.h
$ # write to first line "#define PJ_HAS_IPV6 1"
$ make dep
$ make -j 2
$ sudo cp pjsip-apps/bin/pjsua-x86_64-unknown-linux-gnu /usr/sbin/pjsua
$ pjsua # test if command works , make sure asterisk is not running (sudo service asterisk stop)
$ sudo make -C pjsip-apps/src/python install

```

# Testing

```
$ sudo ./runtests.py -l
$ sudo ./runtests.py
$ grep "^    <testcase.*/>$" asterisk-test-suite-report.xml | cut -d'"' -f2 &> _passing_tests.txt
$ for i in `cat _passing_tests.txt`; do sudo ./runtests.py -t $i; sleep 5; done &> _stack_gathering_passing_tests.log
```

list of succeeding tests:
```

tests/apps/channel_redirect
tests/apps/chanspy/chanspy_barge
tests/apps/chanspy/chanspy_w_mixmonitor
tests/apps/dial/action_post_answer/called_party_continue
tests/apps/dial/action_post_answer/party_transfer
tests/apps/dial/peer_h_exten
tests/apps/directed_pickup/pickup_chan
tests/apps/disa/nominal/authenticate
tests/apps/disa/nominal/no_authentication
tests/apps/disa/nominal/no_context
tests/apps/disa/off-nominal/bad_auth
tests/apps/disa/off-nominal/invalid_exten
tests/apps/incomplete/sip_incomplete
tests/apps/queues/position_priority_maxlen
tests/apps/queues/queue_baseline
tests/apps/queues/set_penalty
tests/apps/voicemail/authenticate_extensions
tests/apps/voicemail/authenticate_invalid_mailbox
tests/apps/voicemail/authenticate_invalid_password
tests/apps/voicemail/func_vmcount
tests/asyncagi/asyncagi_break
tests/cdr/batch_cdrs
tests/cdr/cdr_manipulation/console_fork_after_busy_forward
tests/cdr/cdr_manipulation/console_fork_before_dial
tests/cdr/cdr_manipulation/nocdr
tests/cdr/cdr_properties/blind-transfer-accountcode
tests/cdr/cdr_properties/cdr_userfield
tests/cdr/cdr_unanswered_yes
tests/cdr/console_dial_sip_answer
tests/cdr/console_dial_sip_busy
tests/cdr/console_dial_sip_congestion
tests/cdr/console_dial_sip_transfer
tests/cdr/originate-cdr-disposition
tests/channels/SIP/SDP_offer_answer
tests/channels/SIP/device_state_notification
tests/channels/SIP/handle_response_address_incomplete
tests/channels/SIP/info_dtmf
tests/channels/SIP/invite_no_totag
tests/channels/SIP/message_disabled
tests/channels/SIP/noload_res_srtp
tests/channels/SIP/noload_res_srtp_attempt_srtp
tests/channels/SIP/options
tests/channels/SIP/realtime_nosipregs
tests/channels/SIP/realtime_sipregs
tests/channels/SIP/register_forbidden_retry/no_retry
tests/channels/SIP/rfc2833_dtmf_detect
tests/channels/SIP/route
tests/channels/SIP/sendrpid/pai/trust_legacy/pres_allow
tests/channels/SIP/sendrpid/pai/trust_legacy/pres_prohib
tests/channels/SIP/sendrpid/rpid/trust_legacy/pres_allow
tests/channels/SIP/session_timers/basic_uac_refresh
tests/channels/SIP/session_timers/basic_uac_teardown
tests/channels/SIP/session_timers/basic_uas_refresh
tests/channels/SIP/session_timers/basic_uas_teardown
tests/channels/SIP/session_timers/uas_minimum_se
tests/channels/SIP/session_timers/uas_originate/large_minse_large_se
tests/channels/SIP/session_timers/uas_originate/medium_minse_large_se
tests/channels/SIP/session_timers/uas_originate/medium_minse_medium_se
tests/channels/SIP/session_timers/uas_originate/no_minse_large_se
tests/channels/SIP/session_timers/uas_originate/no_minse_medium_se
tests/channels/SIP/session_timers/uas_originate/no_minse_small_se
tests/channels/SIP/session_timers/uas_originate/small_minse_large_se
tests/channels/SIP/session_timers/uas_originate/small_minse_medium_se
tests/channels/SIP/session_timers/uas_originate/small_minse_small_se
tests/channels/SIP/sip_attended_transfer
tests/channels/SIP/sip_blind_transfer/callee_refer_only
tests/channels/SIP/sip_blind_transfer/callee_with_reinvite
tests/channels/SIP/sip_blind_transfer/caller_refer_only
tests/channels/SIP/sip_blind_transfer/caller_with_reinvite
tests/channels/SIP/sip_cause
tests/channels/SIP/sip_channel_params
tests/channels/SIP/sip_hold
tests/channels/SIP/sip_hold_direct_media
tests/channels/SIP/sip_register
tests/channels/SIP/sip_register_domain_acl
tests/channels/SIP/sip_srtp/srtp_call
tests/channels/SIP/sip_tls_register
tests/channels/SIP/tcpauthlimit/tcp_client_scenario
tests/channels/SIP/tcpauthtimeout/timeout_should_happen
tests/channels/SIP/tcpauthtimeout/timeout_should_not_happen
tests/channels/SIP/use_contact_from_200
tests/channels/iax2/basic-call
tests/channels/local/local_app
tests/connected_line/macro
tests/example
tests/fastagi/channel-status
tests/fastagi/connect
tests/fastagi/database
tests/fastagi/execute
tests/fastagi/hangup
tests/funcs/func_global
tests/funcs/func_srv
tests/manager/login
tests/pbx/call-files
tests/pbx/call_file_retries_alwaysdelete
tests/pbx/call_file_retries_archive
tests/pbx/call_file_retries_fail
tests/pbx/call_file_retries_success
tests/pbx/create_call_files
tests/redirecting/macro
```


mixmonitor test was hanging, so killed it


# older version of testsuite

```
$ http://downloads.asterisk.org/pub/telephony/asterisk/old-releases/ChangeLog-1.8.10.1
$ git log --before="2012-04-01"
$ https://github.com/asterisk/testsuite/tree/340c1149f1bdabb8cb4678ffd167bade1726b346
```

I just used newer version, about 100 tests succeeded in the newer testsuite with >900 tests I believe.
