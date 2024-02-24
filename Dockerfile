FROM golang:1.22-bookworm AS build

ARG VERSION

WORKDIR /src

COPY ./ ./

RUN go build -ldflags "-X main.version=${VERSION}"


FROM debian:bookworm-slim

WORKDIR /

COPY --from=build /src/auth-server /bin/auth-server

EXPOSE 6080

VOLUME /etc/auth-server

ENTRYPOINT ["/bin/auth-server"]
CMD ["-config", "/etc/auth-server/auth-server.jsonc"]
