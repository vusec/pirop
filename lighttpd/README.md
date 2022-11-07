# Compilation and Installation

```
$ sudo apt-get install libpcre libpcre3 libpcre3-dev zlib1g-dev zlib1g libldap2-dev libbz2-dev libfam-dev libgamin-dev libgdbm-dev libmemcached-dev libxml2-dev liblua50-dev liblualib50-dev lua5.3 liblua5.3-dev mysql-server libmysqlclient-dev libgssapi3-heimdal sqlite3 libsqlite3-dev libuuid1 uuid-dev libgssapi-krb5-2 libkrb5-dev
$ ./configure --prefix=`pwd`/install --with-lua --with-memcached --with-gdbm --with-mysql --with-geoip --with-ldap --with-webdav-locks --with-webdav-props --with-fam --with-openssl --with-krb5
$ make -j `nproc`
$ make -j `nproc` install
```

# Test

```
$ cd tests
$ ./prepare.sh
$ # cd ../../analysis/wrapper && make lighttpd && cd -
$ TRACE_HTTP=1 VERBOSE=1 ./run-tests.pl &> pirop_stack_tracking.log
$ ./cleanup.sh
```

# modify stop\_proc 

new:
```
#before if:
`pkill lighttpd`;
sleep 1.5;
`pkill lighttpd`;
sleep 1.5;
return 0;
```

old:
```
# before if:
$pid = `pgrep lighttpd`
# in if:
sleep 1;
my $exists = kill(0, $pid);
return -1 if $exists;
return 0;
```

# modify start\_proc

enable stop\_proc in start\_proc function
