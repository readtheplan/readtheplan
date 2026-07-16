ARG PYTHON_IMAGE=python:3.10-slim

FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Build the application and all runtime dependencies into a local wheelhouse.
# The runtime stage installs only these reviewed build outputs, never a package
# selected independently from PyPI.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="readtheplan"
LABEL org.opencontainers.image.description="Terraform plan risk analyzer — classifies changes as safe/review/dangerous/irreversible"
LABEL org.opencontainers.image.url="https://readtheplan.dev"
LABEL org.opencontainers.image.source="https://github.com/readtheplan/readtheplan"
LABEL org.opencontainers.image.licenses="MIT"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 10001 readtheplan \
    && useradd --system --uid 10001 --gid readtheplan \
        --home-dir /home/readtheplan --create-home \
        --shell /usr/sbin/nologin readtheplan

COPY --from=builder /wheels/ /wheels/
RUN python -m pip install --no-cache-dir --no-index \
        --find-links=/wheels readtheplan \
    && rm -rf /wheels

RUN install -d -o readtheplan -g readtheplan /workspace /home/readtheplan/.readtheplan
WORKDIR /workspace

ENV HOME=/home/readtheplan

USER 10001:10001

ENTRYPOINT ["readtheplan"]
CMD ["--help"]
