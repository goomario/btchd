build:
	docker build -t btchd/btchd:1.0 .

run:
	docker run -it -d --name btchd.btchd \
	    -p 8833:8833 \
	    -p 127.0.0.1:8732:8732 \
	    -v /btchd/data:/btchd/data \
	    --env EXTERNALIP=139.196.88.249 \
	    --env MAXTIPAGE=8640000 \
	    btchd/btchd:1.0