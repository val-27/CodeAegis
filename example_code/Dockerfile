# Insecure dockerfile allowing root login
FROM ubuntu:latest
RUN apt-get update && apt-get install -y openssh-server
RUN echo 'root:rootpassword' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
