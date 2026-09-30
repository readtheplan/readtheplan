# Pinned by digest (multi-platform index) so rebuilds are reproducible; bump deliberately.
FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b

LABEL org.opencontainers.image.title="readtheplan"
LABEL org.opencontainers.image.description="Terraform plan risk analyzer — classifies changes as safe/review/dangerous/irreversible"
LABEL org.opencontainers.image.url="https://readtheplan.dev"
LABEL org.opencontainers.image.source="https://github.com/readtheplan/readtheplan"
LABEL org.opencontainers.image.licenses="MIT"

# Install the released version, not whatever PyPI serves at build time. Keep in step with
# pyproject.toml (see RELEASING.md); override with --build-arg READTHEPLAN_VERSION=x.y.z.
# Then add an unprivileged user: the analyzer only needs to read the mounted workspace.
ARG READTHEPLAN_VERSION=0.4.0
RUN pip install --no-cache-dir "readtheplan==${READTHEPLAN_VERSION}" \
    && useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin readtheplan
USER 10001:10001

WORKDIR /workspace

ENTRYPOINT ["readtheplan"]
CMD ["--help"]
