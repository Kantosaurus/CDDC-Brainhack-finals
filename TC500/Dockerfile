FROM ubuntu:22.04@sha256:67211c14fa74f070d27cc59d69a7fa9aeff8e28ea118ef3babc295a0428a6d21

RUN sed -i 's|http://archive.ubuntu.com|http://mirror.kakao.com|g' /etc/apt/sources.list && \
    sed -i 's|http://security.ubuntu.com|http://mirror.kakao.com|g' /etc/apt/sources.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    qemu-user \
    gcc-arm-linux-gnueabihf \
    libc6-armhf-cross \
    && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN mkdir -p cgi-bin

RUN useradd -m -s /bin/bash chall

COPY cgi_server.py /app/cgi_server.py
COPY debug32.cgi /app/cgi-bin/debug32.cgi
COPY index.html /app/index.html
COPY tc100.jpg /app/tc100.jpg
COPY tc200.jpg /app/tc200.jpg
COPY tc300.jpg /app/tc300.jpg
COPY tc400.jpg /app/tc400.jpg
COPY flag /flag

RUN chmod +x /app/cgi-bin/debug32.cgi
RUN chmod 644 /flag

EXPOSE 1004

ENV QEMU_PATH="/usr/bin/qemu-arm"
ENV ARM_LIBC_PATH="/usr/arm-linux-gnueabihf"

USER chall

CMD ["python3", "/app/cgi_server.py"]