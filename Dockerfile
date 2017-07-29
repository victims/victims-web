FROM alpine:latest

ENV APP_SRC=/opt/source \
    VICTIMS_BASE_DIR=/var/run/victims

RUN apk --update --no-cache add \
        python python-dev py2-pip py-cffi \
        g++ \
    && install -d ${VICTIMS_BASE_DIR} ${APP_SRC}

ADD *requirements.txt /tmp/
RUN pip install --no-cache-dir \
        -r /tmp/requirements.txt \
        -r /tmp/dev-requirements.txt \
        -r /tmp/test-requirements.txt

WORKDIR ${APP_SRC}
ENV PYTHONPATH=${APP_SRC}

VOLUME ["${VICTIMS_BASE_DIR}"]

CMD ["python", "-m", "victims.web"]
