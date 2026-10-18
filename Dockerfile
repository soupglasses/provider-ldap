# SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
# SPDX-License-Identifier: MIT
FROM golang:1.27.2-alpine3.23@sha256:9e45f0eb4a63ed37ad6e604950407558b7c738e34e015ae77a5d4ad369cde079 AS generate
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
RUN --mount=type=cache,id=provider-ldap-go-build,target=/root/.cache/go-build apk add --no-cache bash && \
    go install golang.org/x/tools/cmd/goimports@v0.52.0 && \
    go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.20.1 && \
    go install github.com/crossplane/crossplane-tools/cmd/angryjet@v0.0.0-20260719180100-659f1dc036c5 && \
    go install github.com/google/yamlfmt/cmd/yamlfmt@v0.21.0
COPY config ./config
COPY cmd/generate ./cmd/generate
COPY apis ./apis
COPY internal ./internal
COPY hack ./hack
COPY generate.sh ./
RUN --mount=type=cache,id=provider-ldap-go-build,target=/root/.cache/go-build ./generate.sh

FROM generate AS build
COPY cmd/provider ./cmd/provider
RUN --mount=type=cache,id=provider-ldap-go-build,target=/root/.cache/go-build CGO_ENABLED=0 go test -trimpath -buildvcs=false -p=2 ./cmd/provider && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -buildvcs=false -p=2 -o /out/provider ./cmd/provider

FROM generate AS tests-build
COPY integration ./integration
RUN --mount=type=cache,id=provider-ldap-go-build,target=/root/.cache/go-build CGO_ENABLED=0 go test -c -trimpath -ldflags="-s -w" -buildvcs=false -p=2 -tags=system -o /out/integration ./integration

FROM scratch AS generated
COPY --from=generate /src/generated/crds /generated/crds
COPY --from=generate /src/config/schema.json /generated/schema.json

FROM scratch AS generated-source
COPY --from=generate /src/generated/source /

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0 AS runtime
LABEL org.opencontainers.image.source="https://github.com/soupglasses/provider-ldap"
RUN apk add --no-cache ca-certificates
COPY --from=build /out/provider /provider
COPY LICENSE /licenses/provider-ldap-MIT
COPY LICENSES/ /licenses/
USER 65532:65532
ENTRYPOINT ["/provider"]


FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0 AS tests
RUN apk add --no-cache openldap openldap-back-mdb openldap-clients
COPY --from=tests-build /out/integration /tests/integration
ENV LDAP_MODULE_PATH=/usr/lib/openldap
ENTRYPOINT ["/tests/integration"]
