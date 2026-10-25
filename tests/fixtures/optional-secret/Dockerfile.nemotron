# syntax=docker/dockerfile:1
# Official Runpod worker, pinned to its Linux/amd64 manifest.
# Its vLLM release is replaced below with NVIDIA's exact prescribed nightly.
FROM runpod/worker-v1-vllm:v2.30.0@sha256:437ddeda2917d21fdd16c606d472db47129d0ab3ff55041db1801cbd81de475c AS runtime-base

USER root
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    MODEL_NAME=/runpod-volume/models/bolt \
    TOKENIZER_NAME=/runpod-volume/models/bolt \
    MODEL_REVISION="" \
    TOKENIZER_REVISION="" \
    HF_HOME=/cache/huggingface \
    HF_HUB_CACHE=/cache/huggingface/hub \
    HUGGINGFACE_HUB_CACHE=/cache/huggingface/hub \
    HF_DATASETS_CACHE=/cache/huggingface/datasets \
    HF_HUB_DISABLE_TELEMETRY=1 \
    VLLM_CACHE_ROOT=/cache/vllm \
    VLLM_NO_USAGE_STATS=1 \
    VLLM_USE_V2_MODEL_RUNNER=1 \
    VLLM_BUILD_COMMIT=77154ca6116ae34cbfe314beef1016bde9b63989 \
    UV_OVERRIDE="" \
    RUNPOD_LOG_LEVEL=INFO

# Keep CUDA/PyTorch/CUTLASS from the base. Replace the engine and the few
# dependency versions that differ from NVIDIA's nightly; no resolver upgrades.
# Align the inherited OpenTelemetry packages to one compatible release family.
# The original startup and handler run unchanged in the isolated SDK environment.
COPY inference-overlay.lock ./
RUN uv pip uninstall --system runpod vllm-bnb-plugin \
    && uv pip install --system --no-deps --require-hashes -r inference-overlay.lock

# Runpod and vLLM currently require incompatible FastAPI ranges.
COPY requirements.lock ./
RUN python3 -m venv /opt/queue \
    && uv pip install --python /opt/queue/bin/python --require-hashes -r requirements.lock \
    && uv pip check --python /opt/queue/bin/python \
    && /opt/queue/bin/python -c "import sys; sys.path.insert(0, '/src'); import main, handler"

COPY assets.lock.json LICENSE NOTICE ./
COPY licenses ./licenses
COPY scripts/build_checks.py ./scripts/build_checks.py
# Hub requires handler.py in the repository; this is the exact v2.30.0 copy.
COPY handler.py /src/handler.py
RUN python3 scripts/build_checks.py \
    && uv pip freeze --system > /app/inference-packages.txt \
    && mkdir -p /cache/huggingface

# Build-only network access for the exact main model and drafter revisions.
# local_dir avoids dangling cache symlinks. Deploy without a network volume;
# mounting one at /runpod-volume would hide the baked files.
FROM runtime-base AS model-builder
COPY scripts/bake_models.py ./scripts/bake_models.py
RUN --mount=type=secret,id=HF_TOKEN,required=false \
    python3 scripts/bake_models.py \
    && chmod -R a-w /runpod-volume/models

FROM runtime-base AS final
ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 ENFORCE_EAGER=true
ENV SERVED_MODEL_NAME=nemotron-bolt \
    MAX_MODEL_LEN=32768 \
    MAX_NUM_SEQS=1 \
    MAX_CONCURRENCY=1 \
    MAX_NUM_BATCHED_TOKENS=2048 \
    ENABLE_CHUNKED_PREFILL=true \
    GPU_MEMORY_UTILIZATION=0.90 \
    TRUST_REMOTE_CODE=true \
    LOAD_FORMAT=auto \
    TENSOR_PARALLEL_SIZE=1 \
    KV_CACHE_DTYPE=fp8 \
    ATTENTION_BACKEND=FLASHINFER \
    MAMBA_SSM_CACHE_DTYPE=bfloat16 \
    MAMBA_CACHE_DTYPE=bfloat16 \
    SEED=42 \
    LIMIT_MM_PER_PROMPT='{"video":1,"image":1}' \
    VIDEO_PRUNING_RATE=0.5 \
    MEDIA_IO_KWARGS='{"video":{"fps":2,"num_frames":256}}' \
    ENABLE_AUTO_TOOL_CHOICE=true \
    TOOL_CALL_PARSER=qwen3_coder \
    REASONING_PARSER=ultra_v3 \
    GENERATION_CONFIG=vllm \
    DISABLE_UVICORN_ACCESS_LOG=true \
    VLLM_STARTUP_TIMEOUT=1800 \
    REQUEST_TIMEOUT=600 \
    SPECULATIVE_CONFIG='{"method":"dflash","model":"/runpod-volume/models/lilicorr","num_speculative_tokens":7,"rejection_sample_method":"standard","attention_backend":"FLASHINFER","draft_load_config":{"load_format":"auto"}}' \
    VLLM_EXTRA_ARGS="--linear-backend b12x --moe-backend b12x --mamba-backend flashinfer --mamba-cache-mode align --reasoning-parser-plugin /runpod-volume/models/bolt/ultra_v3_reasoning_parser.py"
COPY --from=model-builder /runpod-volume/models/ /runpod-volume/models/
COPY local_model_args.json /local_model_args.json

STOPSIGNAL SIGTERM
# This queue worker exposes no public port. vLLM listens only on loopback.
ENTRYPOINT ["/opt/queue/bin/python", "/src/main.py"]
CMD []
