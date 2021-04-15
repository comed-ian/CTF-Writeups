docker build . -t snek
docker run -it --rm -v $PWD:/chal snek bash 
