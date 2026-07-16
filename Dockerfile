# Pinned to bookworm to prevent silent OS-level changes from floating tag updates
FROM python:3.12-slim-bookworm AS builder
WORKDIR /app
COPY pyproject.toml README.md ./
COPY osintdepintel/ ./osintdepintel/
RUN pip install --no-cache-dir build && python -m build --wheel

# Pinned to bookworm to prevent silent OS-level changes from floating tag updates
FROM python:3.12-slim-bookworm
RUN groupadd -r osint && useradd -r -g osint -d /app -s /sbin/nologin osint
WORKDIR /app
COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl && rm -rf /root/.cache
USER osint
ENTRYPOINT ["osintdepintel"]
CMD ["--help"]
