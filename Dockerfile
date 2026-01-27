# Dockerfile for testing swift-openssl on Linux
FROM swift:6.1-jammy

# Install build dependencies
RUN echo "=== Installing build dependencies ===" \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && echo "=== Dependencies installed ==="

WORKDIR /workspace

# Copy source code
COPY . .

# Verify Swift version
RUN echo "=== Swift Version ===" && swift --version

# Build first (separate step for clearer logging)
RUN echo "=== Building ===" \
    && swift build -v 2>&1 | tail -100 \
    && echo "=== Build complete ==="

# Run tests
RUN echo "=== Running Tests ===" \
    && swift test -v 2>&1 | tail -200 \
    && echo "=== Tests complete ==="

CMD ["swift", "test"]
