FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV USER=user
ENV FLAG=flag
ENV PROB=ropvm
ENV PORT=31123
ENV TIMEOUT=60
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y socat tzdata

RUN ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime
RUN dpkg-reconfigure tzdata

RUN useradd $USER -s /bin/bash

# Remove user, root credential
# Remove user, root credential

RUN mkdir /home/$USER
COPY $FLAG /home/$USER/$FLAG
COPY $PROB /home/$USER/$PROB
COPY program.bin /home/$USER/program.bin

RUN touch /home/$USER/run
RUN echo "#!/bin/bash                       " >> /home/$USER/run && \
    echo "timeout $TIMEOUT /home/$USER/$PROB" >> /home/$USER/run
RUN chown -R root:$USER /home/$USER && \
    chmod 750 /home/$USER           && \
    chmod 750 /home/$USER/run       && \
    chmod 440 /home/$USER/$FLAG     && \
    chmod 750 /home/$USER/$PROB

RUN chmod -R 700 /bin          && \
    chmod -R 700 /sbin         && \
    chmod -R 700 /usr/bin      && \
    chmod -R 700 /usr/sbin     && \
    chmod -R 700 /var/log      && \
    chmod -R 700 /var/tmp      && \
    chmod 644 /etc/passwd      && \
    chmod 644 /etc/passwd-     && \
    chmod 644 /etc/group       && \
    chmod 644 /etc/group-      && \
    chmod 600 /etc/shadow      && \
    chmod 600 /etc/shadow-     && \
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

WORKDIR /home/$USER
USER $USER
CMD socat TCP-LISTEN:$PORT,reuseaddr,fork EXEC:/home/$USER/run
