build:
	docker build -t erich/btchd:1.0 .

run:
	docker run -it -d --name erich.btchd \
	    -p 8833:8833 \
	    -p 127.0.0.1:8832:8832 \
	    -v /btchd/data:/btchd/data \
	    --env EXTERNALIP=139.196.88.249 \
	    --env MAXTIPAGE=8640000 \
	    erich/btchd:1.0