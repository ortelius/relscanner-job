FROM public.ecr.aws/amazonlinux/amazonlinux:2023.11.20260526.0

WORKDIR /app

ENV GO_VERSION=1.26.4
ENV NODE_VERSION=24.16.0
ENV PATH=/usr/local/go/bin:/usr/local/node/bin:$PATH

RUN ["/bin/bash", "-eo", "pipefail", "-c", "\
    dnf update -y && \
    dnf install -y \
      ca-certificates \
      tar \
      gzip \
      xz \
      git \
      java-21-amazon-corretto-devel \
      gcc \
      glibc-devel \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
"]

RUN ["/bin/bash", "-eo", "pipefail", "-c", "\
    case \"$(uname -m)\" in \
      x86_64|amd64) GO_ARCH=amd64; NODE_ARCH=x64 ;; \
      aarch64|arm64) GO_ARCH=arm64; NODE_ARCH=arm64 ;; \
      *) echo \"Unsupported architecture: $(uname -m)\" >&2; exit 1 ;; \
    esac && \
    curl -fsSL \"https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz\" -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm -f /tmp/go.tar.gz && \
    curl -fsSL \"https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz\" -o /tmp/node.tar.xz && \
    mkdir -p /usr/local/node && \
    tar -C /usr/local/node --strip-components=1 -xJf /tmp/node.tar.xz && \
    rm -f /tmp/node.tar.xz && \
    go version && \
    node --version && \
    npm --version \
"]

RUN ["/bin/bash", "-eo", "pipefail", "-c", "\
    npm install -g @cyclonedx/cdxgen && \
    cdxgen --version \
"]

COPY . /app

RUN ["/bin/bash", "-eo", "pipefail", "-c", "\
    go mod tidy && \
    go build -o main . \
"]

ENV ARANGO_HOST=localhost
ENV ARANGO_USER=root
ENV ARANGO_PASS=rootpassword
ENV ARANGO_PORT=8529
ENV GITHUB_APP_ID=2695570
ENV GITHUB_CLIENT_ID=Iv23liVE3QJYlS6BGQRa

EXPOSE 8080

ENTRYPOINT ["/app/main", "process-workflow"]