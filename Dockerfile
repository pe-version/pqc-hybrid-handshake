FROM python:3.12-slim

ENV LIBOQS_VERSION=0.10.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git cmake ninja-build libssl-dev gcc g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch ${LIBOQS_VERSION} \
        https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && mkdir /tmp/liboqs/build && cd /tmp/liboqs/build \
    && cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON .. \
    && ninja install \
    && ldconfig \
    && rm -rf /tmp/liboqs

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY tests ./tests

RUN pip install --no-cache-dir -e ".[dev]"

CMD ["python", "-m", "pqc_hybrid_handshake"]
