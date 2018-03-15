build:
	docker build -t erich/bco:1.0 .

run:
	docker run -it -d --name erich.bco \
	    -p 8333:8333 \
	    -v /bco/data:/bco/data \
	    --env EXTERNALIP=139.196.88.249 \
	    --env MAXTIPAGE=8640000 \
	    erich/bco:1.0