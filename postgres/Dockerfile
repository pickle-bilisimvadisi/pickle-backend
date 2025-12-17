FROM postgres:15-alpine

RUN apk add --no-cache curl jq bash

RUN mkdir -p /vault/tokens

COPY init.sh /init.sh
RUN chmod +x /init.sh

EXPOSE 5432

ENTRYPOINT ["/init.sh"]