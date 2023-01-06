FROM python:3.11-alpine
WORKDIR /app
ADD . /app
RUN pip3 install -r requirements.txt
ENTRYPOINT /app/ci.sh
