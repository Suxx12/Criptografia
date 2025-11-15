# Dockerfile para C3 - Ubuntu 20.10
FROM ubuntu:20.10

# Configurar repositorios antiguos (Ubuntu 20.10 ya no está en repositorios activos)
RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list && \
    sed -i 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list

# Actualizar e instalar OpenSSH cliente y tcpdump
RUN apt-get update && \
    apt-get install -y openssh-client tcpdump && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configurar para conexiones SSH
RUN mkdir -p /root/.ssh

WORKDIR /root

