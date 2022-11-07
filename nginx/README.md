* Install dependencies

```
$ sudo apt-get install libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev libxml2-dev libxslt1-dev libgd-dev libgeoip-dev
```

* Getting and Installing Nginx

```
$ wget http://nginx.org/download/nginx-1.10.2.tar.gz
$ tar zxf nginx-1.10.2.tar.gz
$ cd nginx-1.10.2
$ ./configure --prefix=`pwd`/install --with-cc-opt="-g" --with-http_ssl_module --with-stream --with-mail --with-http_v2_module --with-ipv6 --with-http_addition_module --with-http_sub_module --with-http_auth_request_module --with-http_gzip_static_module --with-http_dav_module --with-http_geoip_module --with-http_gunzip_module --with-http_realip_module --with-http_image_filter_module --with-mail_ssl_module --with-http_mp4_module --with-http_random_index_module --with-http_flv_module --with-http_secure_link_module --with-http_slice_module --with-stream_ssl_module --with-http_stub_status_module --with-http_xslt_module
$ make -j `nproc`
$ make -j `nproc` install
$ cd ../
```

* Wrapping Nginx binary with Stack and Gadget gathering hooks

``` 
$ make -C ../analysis/wrapper nginx
```

* Getting and Running Test suite

```
$ git clone https://github.com/nginx/nginx-tests
$ TEST_NGINX_BINARY=../nginx-1.10.2/objs/nginx TEST_NGINX_VERBOSE=1 TEST_NGINX_LEAVE=1 prove -v proxy_cache.t
$ # TEST_NGINX_LEAVE=1 keeps config and logs files
$ TEST_NGINX_BINARY=../nginx-1.10.2/objs/nginx TEST_NGINX_VERBOSE=1 [TEST_NGINX_LEAVE=1] prove -v . &> pirop_stack_tracking.log

```

