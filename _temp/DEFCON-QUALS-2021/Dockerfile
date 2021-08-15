FROM ubuntu:21.04

#RUN apt-get install software-properties-common -y
#RUN apt-add-repository ppa:pwntools/binutils
RUN apt-get update
RUN apt install software-properties-common apt-transport-https curl -y
RUN apt-get install apt-utils wget -y
RUN apt install git -y
RUN apt-get install gdb gdbserver -y
#RUN git clone https://github.com/longld/peda.git ~/peda
#RUN echo "source ~/peda/peda.py" >> ~/.gdbinit
RUN apt install python3-pip -y
RUN apt-get install python3 python3-dev libssl-dev libffi-dev build-essential -y
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade pwntools
RUN wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
RUN echo source ~/.gdbinit-gef.py >> ~/.gdbinit
# install missing gef dependencies
RUN pip install keystone-engine && pip install ropper
RUN apt install musl
RUN mkdir ./workspace
WORKDIR /workspace/
