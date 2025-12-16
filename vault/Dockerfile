FROM hashicorp/vault:1.21

USER root

RUN mkdir -p /vault/config /vault/file

RUN chown -R vault:vault /vault

COPY ./config.hcl /vault/config/config.hcl

COPY ./init.sh /vault/init.sh

EXPOSE 8200

CMD ["sh", "/vault/init.sh"]