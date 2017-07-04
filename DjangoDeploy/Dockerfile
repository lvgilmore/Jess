FROM python:3.5

MAINTAINER "Sebastian Sch"

RUN apt-get update
RUN apt-get install -y python3-pip python3-dev libpq-dev nginx supervisor vim sudo gcc libsasl2-dev libldap2-dev libssl-dev

RUN pip3 install --upgrade pip
RUN ln -s /usr/local/bin/pip /usr/bin/pip
RUN pip3 install django gunicorn psycopg2 pika Pillow


RUN adduser app_user --disabled-password

RUN mkdir /web
RUN mkdir /static
RUN chown -R app_user:app_user /web
RUN chown -R app_user:app_user /static

ADD /Web /web
RUN pip3 install -r /web/requirements.txt

ADD conf /container/conf
ADD scripts /container/scripts/
# Copy over scripts ADD scripts /container/scripts
RUN chmod 755 /container/scripts/*

# Set up supervisor
RUN ln -s /container/conf/supervisor_app.conf /etc/supervisor/conf.d/
# Set up NGINX
RUN echo "daemon off;" >> /etc/nginx/nginx.conf
RUN rm /etc/nginx/sites-enabled/*
RUN ln -s /container/conf/nginx_app /etc/nginx/sites-enabled/

# Expose port
EXPOSE 80
# Start script
CMD ["/container/scripts/container_start.sh"]
