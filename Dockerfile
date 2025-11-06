FROM ubuntu:25.04

# install python3, pip, cron
RUN apt-get update && apt-get install -y cron python3 python3-pip python3.13-venv

# Setting working directory
WORKDIR /app

# Copying requirements file and installing Python packages
COPY app/requirements.txt /app
RUN python3 -m venv venv
RUN /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copying application code and crontab file
COPY app/ /app/
COPY crontab /etc/cron.d/nessus_cron

# Setting cron job permissions and registering
RUN chmod 0644 /etc/cron.d/nessus_cron
RUN crontab /etc/cron.d/nessus_cron

# Creating log directory
RUN mkdir /logs
RUN touch /logs/cron.log

# Starting cron daemon and keeping container running
#CMD mkdir -p /logs && touch /logs/cron.log && env > /etc/enviroment && cron && tail -f /logs/cron.log
RUN chmod +x /app/entrypoint.sh
CMD ["/app/entrypoint.sh"]
