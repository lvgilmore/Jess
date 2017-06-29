FROM centos/python-27-centos7
MAINTAINER "Geiger"
RUN "pip install --upgrade pip"
RUN "pip install pika"
