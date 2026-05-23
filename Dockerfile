FROM python:3.10-slim

LABEL org.opencontainers.image.title="readtheplan"
LABEL org.opencontainers.image.description="Terraform plan risk analyzer — classifies changes as safe/review/dangerous/irreversible"
LABEL org.opencontainers.image.url="https://readtheplan.dev"
LABEL org.opencontainers.image.source="https://github.com/readtheplan/readtheplan"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /workspace

RUN pip install --no-cache-dir readtheplan

ENTRYPOINT ["readtheplan"]
CMD ["--help"]
