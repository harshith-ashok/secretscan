FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home scanner
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
USER scanner
WORKDIR /repo

RUN git config --global --add safe.directory /repo
ENTRYPOINT ["secretscan"]
CMD ["scan", "."]