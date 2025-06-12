# Docker host server's boot option setting: 
# echo 'GRUB_CMDLINE_LINUX_DEFAULT="vsyscall=emulate"' >> /etc/default/grub
# reboot
FROM ubuntu@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97

ENV DEBIAN_FRONTEND=noninteractive
ENV USER=user
ENV HINT=hint
ENV PROB=prob
ENV PORT=30015
ENV TIMEOUT=60

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y socat tzdata

RUN ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime
RUN dpkg-reconfigure tzdata

RUN useradd $USER -s /bin/bash

RUN mkdir /home/$USER
COPY ./$HINT /home/$USER/$HINT
COPY ./$PROB /home/$USER/$PROB
RUN touch /home/$USER/run
RUN echo "#!/bin/bash                       " >> /home/$USER/run && \
    echo 'export HINT="$(cat /home/$USER/'"$HINT"')"' >> /home/$USER/run && \
    echo "timeout $TIMEOUT /home/$USER/$PROB" >> /home/$USER/run

RUN chown -R root:$USER /home/$USER && \
    chmod 750 /home/$USER           && \
    chmod 755 /home/$USER/run       && \
    chmod 440 /home/$USER/$HINT     && \
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
