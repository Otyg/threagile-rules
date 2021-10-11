######
## Stage 1: Clone the Git repository
######
FROM alpine/git as clone
WORKDIR /app
RUN git clone https://github.com/threagile/threagile.git
COPY ./risks /app/threagile/risks/custom


######
## Stage 2: Build application with Go's build tools
######
FROM golang as build-threagile
ENV GO111MODULE=on
WORKDIR /app
COPY --from=clone /app/threagile /app
COPY ./risks /app/custom
RUN go mod download
RUN go version
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o raa.so raa/raa/raa.go
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o dummy.so raa/dummy/dummy.go
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o demo-rule.so risks/custom/demo/demo-rule.go
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -o threagile
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o missing-monitoring-rule.so risks/custom/missing-monitoring/missing-monitoring-rule.go
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o accidental-logging-of-sensitive-data-rule.so risks/custom/accidental-logging-of-sensitive-data/accidental-logging-of-sensitive-data-rule.go
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o missing-audit-of-sensitive-asset-rule.so risks/custom/missing-audit-of-sensitive-asset/missing-audit-of-sensitive-asset-rule.go
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

RUN mkdir /data

RUN chown -R 1000:1000 /app /data
USER 1000:1000

ENV PATH=/app:$PATH
ENV GIN_MODE=release

ENTRYPOINT ["/app/threagile"]
CMD ["-help"]