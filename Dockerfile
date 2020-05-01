# docker run -it --privileged -p 5996:5996 --net=host -v /var/run/docker.sock:/var/run/docker.sock clab /bin/sh
FROM python:3.8-slim-buster 

COPY clab/*.py clab/config.yaml clab/en.txt clab/
COPY python-netfilterqueue/ netfilterqueue/

RUN apt-get update && \
    apt-get install -y iptables build-essential python-dev libnetfilter-queue-dev git &&\
    pip3 install aiodocker dnslib netaddr dpkt pyyaml netifaces peewee python-iptables &&\
    cd /netfilterqueue && \
    python3 ./setup.py install

EXPOSE 5996
CMD ["python3","/clab/clab.py --run"]