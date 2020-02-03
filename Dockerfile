FROM python:3.8-alpine

ENV OP_VERSION 0.9.2
RUN apk add --no-cache zip \
  && wget https://cache.agilebits.com/dist/1P/op/pkg/v${OP_VERSION}/op_linux_386_v${OP_VERSION}.zip \
  && unzip op_linux_386_v${OP_VERSION}.zip \
  && mv op /usr/local/bin \
  && rm op_linux_386_v${OP_VERSION}.zip \
  && apk del zip

