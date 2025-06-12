FROM ubuntu@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97

ENV DEBIAN_FRONTEND=noninteractive
# ENV USER=user
ENV FLAG=flag
ENV PROB=prob
ENV PORT=35001
ENV TIMEOUT=60

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y socat tzdata

RUN ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime
RUN dpkg-reconfigure -f noninteractive tzdata

RUN echo "root:1234" | chpasswd


COPY ./$FLAG /$FLAG
COPY ./$PROB /root/room/$PROB
RUN touch /root/room/run
RUN echo "#!/bin/bash" >> /root/room/run \
    && echo "timeout $TIMEOUT /root/room/$PROB" >> /root/room/run


RUN chown -R root:root /root \
    && chmod 750 /root \
    && chmod 750 /root/room/run \
    && chmod 440 /$FLAG \
    && chmod 750 /root/room/$PROB


RUN HASH=$(md5sum /${FLAG} | cut -d ' ' -f1) \
 && mv /${FLAG} /${FLAG}-$HASH \
 && chmod 440 /${FLAG}-$HASH


RUN chmod -R 700 /bin          && \
    chmod -R 700 /sbin         && \
    chmod -R 700 /usr/bin      && \
    chmod -R 700 /usr/sbin     && \
    chmod -R 700 /var/log      && \
    chmod -R 700 /var/tmp      && \
    chmod 644 /etc/passwd      && \
    chmod 644 /etc/group       && \
    chmod 600 /etc/shadow      && \
    chmod 700 /var             && \
    chmod 700 /tmp             && \
    chmod 600 /dev/shm         && \
    chmod 755 /bin             && \
    chmod 755 /sbin            && \
    chmod 755 /usr/bin         && \
    chmod 755 /usr/sbin        && \
    chmod 755 /var             && \
    chmod 755 /var/log         && \
	chmod 755 /bin/id          && \
    chmod 755 /bin/ls          && \
    chmod 755 /bin/cat         && \
    chmod 755 /bin/sh          && \
    chmod 755 /bin/dash        && \
    chmod 755 /bin/bash        && \
    chmod 755 /usr/bin/whoami  && \
    chmod 755 /usr/bin/groups  && \
    chmod 755 /usr/bin/timeout && \
    chmod 755 /usr/bin/socat


RUN mkdir -p /root/room/bin \
             /root/room/lib/x86_64-linux-gnu \
             /root/room/lib64 \
 && cp /bin/sh                          /root/room/bin/ \
 && cp /usr/bin/socat                   /root/room/bin/socket \
 && cp /usr/bin/timeout                 /root/room/bin/timeout \
 && cp /lib/x86_64-linux-gnu/libc.so.6   /root/room/lib/x86_64-linux-gnu/ \
 && cp /usr/lib/x86_64-linux-gnu/libpcre2-8.so.0 /root/room/lib/x86_64-linux-gnu/ \
 && cp /usr/lib/x86_64-linux-gnu/libselinux.so.1 /root/room/lib/x86_64-linux-gnu/ \
 && cp /lib/x86_64-linux-gnu/libtinfo.so.6      /root/room/lib/x86_64-linux-gnu/ \
 && cp /lib64/ld-linux-x86-64.so.2               /root/room/lib64 \
 && chown -R root:root /root/room \
 && chmod -R 755     /root/room

WORKDIR /root/room
USER root
CMD socat TCP-LISTEN:$PORT,reuseaddr,fork EXEC:"/root/room/run,stderr"
