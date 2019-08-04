FROM centos/python-27-centos7
USER root

RUN yum -y install sudo

RUN sed -i 's/#   StrictHostKeyChecking ask/StrictHostKeyChecking no/' /etc/ssh/ssh_config
RUN echo 'UserKnownHostsFile /dev/null' >> /etc/ssh/ssh_config
RUN echo 'IdentityFile /pf9/ansible-key' >> /etc/ssh/ssh_config

WORKDIR  /opt
RUN mkdir -p  /opt/pf9/express
ADD ./ /opt/pf9/express
RUN /opt/pf9/express/pf9-express -i

ENTRYPOINT ["/opt/pf9/express/pf9-express"]
