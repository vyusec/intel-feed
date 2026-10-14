FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY third_party ./third_party
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/zoli-intel ./cmd/zoli-intel

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 zoli
WORKDIR /app
COPY --from=build /out/zoli-intel /usr/local/bin/zoli-intel
COPY config.yaml ./
COPY rules ./rules
RUN mkdir data secrets && chown -R zoli:zoli /app
USER zoli
EXPOSE 8080
ENTRYPOINT ["zoli-intel"]
CMD ["serve", "--config", "/app/config.yaml"]
