# Compilation and Installation

```
$ wget http://apache.cs.utah.edu//httpd/httpd-2.4.25.tar.gz
$ tar -xf httpd-2.4.25.tar.gz
$ sudo apt-get install libapr1-dev libaprutil1-dev 
$ ./configure --prefix=`pwd`/install --enable-modules=reallyall --enable-load-all-modules --enable-mods-static=reallyall --with-mpm=worker
$ make -j 2
$ make -j 2 install
$ install/bin/httpd -l # list all modules statically linked && enabled
```

# Testing

```
$ svn checkout http://svn.apache.org/repos/asf/httpd/test/framework/trunk/ httpd-framework
$ cd httpd-framework
$ sudo perl -MCPAN -e 'install Bundle::ApacheTest'
$ sudo perl -MCPAN -e 'install HTTP::DAV'
$ sudo perl -MCPAN -e 'install DateTime'
$ sudo perl -MCPAN -e 'install AnyEvent' # disconnect from internet
$ sudo perl -MCPAN -e 'install Protocol::HTTP2::Client'
$ sudo perl -MCPAN -e 'install Test::Harness'
$ sudo perl -MCPAN -e 'install Crypt::SSLeay'
$ sudo perl -MCPAN -e 'install Net::SSLeay'
$ sudo perl -MCPAN -e 'install IO::Socket::SSL'
$ sudo perl -MCPAN -e 'install LWP::Protocol::https'
$ perl Makefile.PL -apxs /home/box16/projects/pirop-code/httpd/httpd-2.4.25/install/bin/apxs
$ t/TEST t/http11/post.t -verbose=1
$ #set following in t/conf/httpd.conf:
 66 <IfModule worker.c>
    ..
 72     ServerLimit          1
 73     StartServers         1
 74     MinSpareThreads      1
 75     MaxSpareThreads      1
 76     ThreadsPerChild      1
 77     MaxClients           1
$ t/TEST -verbose=1 &> _test_results.log
```
