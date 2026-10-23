# SPDX-FileCopyrightText: 2026 Sofie Finnes <sofie+git@finnes.dev>
# SPDX-License-Identifier: Apache-2.0
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.23@sha256:754d5200fc3edae76d3b6598a9a3fac7e74981ee6a5413ab955025f185753ef2 AS generate
WORKDIR /src
COPY go.mod go.sum ./
RUN apk add --no-cache bash ca-certificates
RUN go mod download
RUN --mount=type=cache,id=provider-ldap-go-build,target=/root/.cache/go-build go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.20.1 && go install github.com/google/yamlfmt/cmd/yamlfmt@v0.21.0
COPY apis ./apis
COPY hack ./hack
COPY generate.sh ./
RUN --mount=type=cache,id=provider-ldap-go-build,target=/root/.cache/go-build ./generate.sh

FROM generate AS unit-tests
COPY cmd ./cmd
RUN --mount=type=cache,id=provider-ldap-go-build,target=/root/.cache/go-build test -z "$(gofmt -l cmd apis)" && mkdir -p /out && CGO_ENABLED=0 go test -trimpath -coverprofile=/out/coverage.out -buildvcs=false -p=2 ./cmd/... ./apis/...

FROM unit-tests AS build
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,id=provider-ldap-go-build,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -buildvcs=false -p=2 -o /out/provider ./cmd/provider

FROM generate AS tests-build
COPY integration ./integration
RUN --mount=type=cache,id=provider-ldap-go-build,target=/root/.cache/go-build test -z "$(gofmt -l integration)" && CGO_ENABLED=0 go test -c -trimpath -ldflags="-s -w" -buildvcs=false -p=2 -o /out/check ./integration

FROM scratch AS generated
COPY --from=generate /src/generated/crds /generated/crds
COPY --from=generate /src/apis /apis

FROM scratch AS coverage
COPY --from=unit-tests /out/coverage.out /coverage.out

FROM alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 AS runtime
LABEL org.opencontainers.image.source="https://github.com/soupglasses/provider-ldap"
COPY --from=generate /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/provider /provider
COPY LICENSE /licenses/provider-ldap-Apache-2.0
COPY LICENSES/ /licenses/
USER 65532:65532
ENTRYPOINT ["/provider"]

FROM alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 AS tests
RUN apk add --no-cache openldap openldap-back-mdb openldap-clients
COPY --from=tests-build /out/check /tests/check
USER 65532:65532
ENTRYPOINT ["/tests/check"]
