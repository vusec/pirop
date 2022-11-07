wrapper: wrapper.c
	gcc wrapper.c -o wrapper

nginx: wrapper
	cd ../../nginx/nginx-1.10.2/ && rm -f objs/nginx objs/nginx.orig
	cd ../../nginx/nginx-1.10.2/ && make
	cd ../../nginx/nginx-1.10.2/ && mv objs/nginx objs/nginx.orig
	cp wrapper ../../nginx/nginx-1.10.2/objs/nginx

lighttpd: wrapper
	cd ../../lighttpd/lighttpd-1.4.45/ && rm -f src/lighttpd src/lighttpd.orig
	cd ../../lighttpd/lighttpd-1.4.45/ && make
	cd ../../lighttpd/lighttpd-1.4.45/ && mv src/lighttpd src/lighttpd.orig
	cp wrapper ../../lighttpd/lighttpd-1.4.45/src/lighttpd

httpd: wrapper
	cd ../../httpd/httpd-2.4.25/ && rm -f install/bin/httpd install/bin/httpd.orig
	cd ../../httpd/httpd-2.4.25/ && make install
	cd ../../httpd/httpd-2.4.25/ && mv install/bin/httpd install/bin/httpd.orig
	cp wrapper ../../httpd/httpd-2.4.25/install/bin/httpd

asterisk: wrapper
	sudo cp /usr/sbin/asterisk.real_orig /usr/sbin/asterisk.orig
	sudo cp wrapper /usr/sbin/asterisk

all: wrapper nginx lighttpd

