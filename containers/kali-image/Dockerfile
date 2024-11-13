FROM docker.io/kalilinux/kali-rolling

RUN apt update && apt -y install sudo nmap procps net-tools iproute2 python3 python2 hydra openssh-client

RUN adduser uosec && sudo usermod -aG sudo uosec 

COPY sudoers /etc/sudoers

COPY hosts /etc/hosts

WORKDIR /home/uosec

COPY --chown=uosec pies.lst users.lst MISSION.txt /home/uosec

USER uosec

COPY motd /home/uosec/.motd

RUN echo "cat /home/uosec/.motd" >> /home/uosec/.bashrc
