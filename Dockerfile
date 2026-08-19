FROM python:3.10-slim@sha256:a78e4529630cfe8c5199cafd6e0c28ee1579a13f86274396d8b6b2d80367aa3a AS builder

# Build the checked-out package and its runtime dependencies into a local
# wheelhouse. The runtime stage never resolves readtheplan from PyPI.
COPY pyproject.toml README.md LICENSE /build/
COPY src/ /build/src/
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels /build

FROM python:3.10-slim@sha256:a78e4529630cfe8c5199cafd6e0c28ee1579a13f86274396d8b6b2d80367aa3a AS runtime

LABEL org.opencontainers.image.title="readtheplan"
LABEL org.opencontainers.image.description="Terraform plan risk analyzer — classifies changes as safe/review/dangerous/irreversible"
LABEL org.opencontainers.image.url="https://readtheplan.dev"
LABEL org.opencontainers.image.source="https://github.com/readtheplan/readtheplan"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=builder /wheels/ /wheels/
RUN python -m pip install --no-cache-dir --no-compile --no-index \
        --find-links=/wheels readtheplan \
    && rm -rf /wheels \
    && groupadd --gid 10001 readtheplan \
    && useradd --uid 10001 --gid readtheplan \
        --home-dir /home/readtheplan --create-home \
        --shell /usr/sbin/nologin readtheplan \
    && install -d -o readtheplan -g readtheplan \
        /workspace /home/readtheplan/.readtheplan

ENV HOME=/home/readtheplan \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /workspace

USER 10001:10001

ENTRYPOINT ["readtheplan"]
CMD ["--help"]
