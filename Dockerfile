FROM centos/python-27-centos7
USER root

RUN yum -y install sudo

WORKDIR  /opt
RUN mkdir -p  /opt/pf9/express
ADD ./ /opt/pf9/express
RUN /opt/pf9/express/pf9-express -i

ENTRYPOINT /opt/pf9/express/pf9-express 