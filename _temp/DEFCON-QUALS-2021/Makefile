build: Dockerfile
	docker build . -t ubuntu:21.04_musl

run:
	docker run -it -v $(PWD):/workspace ubuntu:21.04_musl bash 

attach:
	docker exec -it $$(echo $$(docker ps -q | head -1)) bash
