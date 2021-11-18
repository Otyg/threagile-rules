######
## Stage 1: Clone the Git repository
######
FROM alpine/git as clone
WORKDIR /app
RUN git clone https://github.com/threagile/threagile.git


######
## Stage 2: Build application with Go's build tools
######
FROM golang as build-threagile
ENV GO111MODULE=on
WORKDIR /app
COPY --from=clone /app/threagile /app
COPY ./risks /app/custom
COPY ./build-threagile.sh /app/
RUN chmod +x build-threagile.sh && ./build-threagile.sh
# add the -race parameter to go build call in order to instrument with race condition detector: https://blog.golang.org/race-detector

######
## Stage 3: Make final small image
######
FROM alpine

# label used in other scripts to filter
LABEL type="threagile"
RUN apk add --update --no-cache graphviz ttf-freefont && apk add ca-certificates && apk add curl && rm -rf /var/cache/apk/*

# https://stackoverflow.com/questions/34729748/installed-go-binary-not-found-in-path-on-alpine-linux-docker
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2

WORKDIR /app

COPY --from=build-threagile /app/threagile /app/threagile
COPY --from=build-threagile /app/raa.so /app/raa.so
COPY --from=build-threagile /app/dummy.so /app/dummy.so
COPY --from=build-threagile /app/demo-rule.so /app/demo-rule.so
COPY --from=build-threagile /app/LICENSE.txt /app/LICENSE.txt
COPY --from=build-threagile /app/report/template/background.pdf /app/background.pdf
COPY --from=build-threagile /app/support/openapi.yaml /app/openapi.yaml
COPY --from=build-threagile /app/support/schema.json /app/schema.json
COPY --from=build-threagile /app/support/live-templates.txt /app/live-templates.txt
COPY --from=build-threagile /app/support/render-data-asset-diagram.sh /app/render-data-asset-diagram.sh
COPY --from=build-threagile /app/support/render-data-flow-diagram.sh /app/render-data-flow-diagram.sh
COPY --from=build-threagile /app/server /app/server
COPY --from=build-threagile /app/demo/example/threagile.yaml /app/threagile-example-model.yaml
COPY --from=build-threagile /app/demo/stub/threagile.yaml /app/threagile-stub-model.yaml
COPY --from=build-threagile /app/missing-monitoring-rule.so /app/missing-monitoring-rule.so
COPY --from=build-threagile /app/accidental-logging-of-sensitive-data-rule.so /app/accidental-logging-of-sensitive-data-rule.so
COPY --from=build-threagile /app/missing-audit-of-sensitive-asset-rule.so /app/missing-audit-of-sensitive-asset-rule.so
COPY --from=build-threagile /app/credential-stored-outside-of-vault-rule.so /app/credential-stored-outside-of-vault-rule.so
COPY --from=build-threagile /app/insecure-handling-of-sensitive-data-rule.so /app/insecure-handling-of-sensitive-data-rule.so
COPY --from=build-threagile /app/running-as-privileged-user.so /app/running-as-privileged-user.so
COPY --from=build-threagile /app/use-of-weak-cryptography.so /app/use-of-weak-cryptography.so
COPY --from=build-threagile /app/secure-communication.so /app/secure-communication.so
RUN mkdir /data

RUN chown -R 1000:1000 /app /data
USER 1000:1000

ENV PATH=/app:$PATH
ENV GIN_MODE=release

ENTRYPOINT ["/app/threagile", "-custom-risk-rules-plugins", "accidental-logging-of-sensitive-data-rule.so,missing-monitoring-rule.so,missing-audit-of-sensitive-asset-rule.so,credential-stored-outside-of-vault-rule.so,insecure-handling-of-sensitive-data-rule.so,running-as-privileged-user.so,use-of-weak-cryptography.so,secure-communication.so"]
CMD ["-help"]
