# build stage
FROM tiangolo/uwsgi-nginx-flask:python3.9 as build-stage

COPY / /python-flask

WORKDIR /python-flask

ENV APP_DEBUG=

ENV APP_KEY=

ENV JWT_SECRET_KEY=

RUN pip install -r ./requirements.txt --no-cache-dir

CMD ["waitress-serve", "app:app"]
