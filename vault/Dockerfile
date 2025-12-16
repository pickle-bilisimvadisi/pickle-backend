FROM hashicorp/vault:1.21

USER root

RUN apk add --no-cache jq bash

RUN mkdir -p /vault/config /vault/file

COPY ./init.sh /vault/init.sh
COPY ./sync-env.sh /vault/sync-env.sh

RUN chmod +x /vault/init.sh /vault/sync-env.sh

COPY ./config.hcl /vault/config/config.hcl

RUN chown -R vault:vault /vault

EXPOSE 8200

CMD ["/vault/init.sh"]