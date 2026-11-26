# Image built by goreleaser from the release binary (see .goreleaser.yaml).
# Alpine keeps a shell for GitLab CI and Azure Pipelines container jobs.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -H -u 10001 scanner
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/attackscout-agent /usr/local/bin/attackscout-agent
USER scanner
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/attackscout-agent"]
CMD ["scan", "--root", "/src", "--project", "/src"]
