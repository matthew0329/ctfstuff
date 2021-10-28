FROM ubuntu:20.04

RUN apt-get update \ 
    && DEBIAN_FRONTEND=noninteractive apt-get -y install xinetd \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m chall && rm -f /home/chall/*

COPY ./bin/chall /home/chall/
COPY ./chall.xinetd /etc/xinetd.d/chall
COPY ./flag.txt /

RUN chown -R root:root /home/chall && \
    chmod -R 755 /home/chall

EXPOSE 1337

CMD ["/usr/sbin/xinetd","-dontfork"]
