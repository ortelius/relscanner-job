FROM cgr.dev/chainguard/go@sha256:e797f1db0ae44e2d2ea4618a8be724f5a3c05f842af2ba47eadc0e573dad78ce AS builder
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /app
COPY . /app

RUN go mod tidy && \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:fa0d07a6a352921b778c4da11d889b41d9ef8e99c69bc2ec1f8c9ec46b2462e9
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /app

COPY --from=builder /app/main .

ENV ARANGO_HOST=localhost
ENV ARANGO_USER=root
ENV ARANGO_PASS=rootpassword
ENV ARANGO_PORT=8529
ENV GITHUB_APP_ID=2695570
ENV GITHUB_CLIENT_ID=Iv23liVE3QJYlS6BGQRa

EXPOSE 8080

ENTRYPOINT [ "/app/main", "process-workflow" ]
