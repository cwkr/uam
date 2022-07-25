FROM golang:1.18-bullseye AS build

WORKDIR /src

COPY ./ ./

RUN go build


FROM debian:bullseye-slim

WORKDIR /

COPY --from=build /src/auth-server /bin/auth-server

EXPOSE 6080

USER nonroot:nonroot

ENTRYPOINT ["/bin/auth-server", "-config", "/etc/auth-server/auth-server-json"]
