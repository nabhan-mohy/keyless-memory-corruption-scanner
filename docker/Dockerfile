# syntax=docker/dockerfile:1.6
# -----------------------------------------------------------------------------
# KMCS development and verification environment
#
# Base: Debian 12 (bookworm), chosen because ASan reserves its shadow memory
# reliably inside it.  The Kali container we developed on did not, which
# prevented the memory-safety classification pipeline from being verified
# against real sanitizer evidence.
#
# Contents:
#   * Python 3.11 (Debian 12 default)
#   * clang-14, llvm-14, lld-14 -- the clang toolchain used by the demo lab
#   * AFL++ 4.21c built from source -- the version whose LTO plugin works
#     with LLVM 14 and whose fork server is compatible with the demo targets
#   * gdb, make, binutils, git -- the supporting tools KMCS expects
#   * The KMCS source tree, installed in editable mode
#
# Build:
#   docker build -f docker/Dockerfile -t kmcs:latest .
#
# Run tests:
#   docker run --rm kmcs:latest pytest tests -m "not integration" -q
#
# Run the end-to-end demo:
#   docker run --rm kmcs:latest pytest tests/integration -q -m integration -s
# -----------------------------------------------------------------------------
FROM debian:12-slim

ARG DEBIAN_FRONTEND=noninteractive
ARG AFLPP_VERSION=4.21c

# --- system dependencies ----------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang-14 \
        llvm-14 \
        libclang-rt-14-dev \
        lld-14 \
        gdb \
        git \
        make \
        python3 \
        python3-venv \
        python3-pip \
        curl \
        file \
        locales \
    && rm -rf /var/lib/apt/lists/*

# --- locale (Textual and Rich like UTF-8) ----------------------------------
RUN sed -i 's/# en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen \
 && locale-gen
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

# --- unversioned tool names ------------------------------------------------
# KMCS calls `clang`, `llvm-symbolizer`, and `ld.lld` without a version
# suffix.  Debian installs them with `-14` suffixes.  Symlink them.
RUN ln -sf /usr/bin/clang-14 /usr/bin/clang \
 && ln -sf /usr/bin/clang++-14 /usr/bin/clang++ \
 && ln -sf /usr/bin/llvm-symbolizer-14 /usr/bin/llvm-symbolizer \
 && ln -sf /usr/bin/ld.lld-14 /usr/bin/ld.lld

# --- AFL++ from source -----------------------------------------------------
# Debian 12 ships AFL++ 4.05c, whose afl-clang-lto does not link correctly
# against LLVM 14 for our targets.  Building 4.21c from source produces a
# working afl-clang-lto, afl-clang-fast, and afl-fuzz.
RUN git clone --depth 1 --branch "v${AFLPP_VERSION}" \
        https://github.com/AFLplusplus/AFLplusplus /opt/aflpp \
 && cd /opt/aflpp \
 && make distrib \
 && make install \
 && rm -rf /opt/aflpp

# --- AFL++ compiler wrapper symlinks ---------------------------------------
# ``make install`` places a single binary at /usr/local/bin/afl-cc and
# expects symlinks named after each wrapper.  Debian's build does not create
# them.  Create the ones KMCS looks for.
RUN ln -sf /usr/local/bin/afl-cc /usr/local/bin/afl-clang-fast \
 && ln -sf /usr/local/bin/afl-cc /usr/local/bin/afl-clang-lto \
 && ln -sf /usr/local/bin/afl-cc /usr/local/bin/afl-clang \
 && ln -sf /usr/local/bin/afl-cc /usr/local/bin/afl-gcc \
 && ln -sf /usr/local/bin/afl-cc /usr/local/bin/afl-g++

# --- the KMCS source tree --------------------------------------------------
WORKDIR /opt/kmcs
COPY pyproject.toml README.md ./
COPY src ./src
COPY tests ./tests
COPY tests-02 ./tests-02
COPY scripts ./scripts

# The docs directory is optional during early builds; create it so COPY of
# subdirectories does not fail.
RUN mkdir -p docs

# --- install KMCS in editable mode ----------------------------------------
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip wheel setuptools \
 && /opt/venv/bin/pip install -e ".[dev,tui]"

ENV PATH="/opt/venv/bin:${PATH}"

# --- build-time sanity checks ---------------------------------------------
# Fail the build immediately if the toolchain or the package is broken.
RUN set -eux; \
    python -c "import kmcs; print('KMCS', kmcs.__version__)"; \
    python -c "import textual; print('textual', textual.__version__)"; \
    for tool in clang afl-fuzz afl-clang-fast afl-clang-lto llvm-symbolizer gdb; do \
        if ! command -v "$tool" >/dev/null 2>&1; then \
            echo "MISSING TOOL: $tool" >&2; \
            exit 1; \
        fi; \
        echo "found: $(command -v $tool)"; \
    done

# Default action is to run the non-integration test suite.
CMD ["python", "-m", "pytest", "tests", "-m", "not integration", "-q"]
