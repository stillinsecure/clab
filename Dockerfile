# docker run -it --privileged -p 5996:5996 --net=host -v /var/run/docker.sock:/var/run/docker.sock clab /bin/sh
FROM python:3.6.10

COPY *.py config.yaml en.txt clab/

RUN apt-get update && \
    apt-get install -y iptables build-essential python-dev libnetfilter-queue-dev &&\
    pip3 install aiodocker dnslib netaddr dpkt pyyaml netifaces peewee python-iptables NetfilterQueue

EXPOSE 5996
CMD ["python3","/clab/clab.py --run"]