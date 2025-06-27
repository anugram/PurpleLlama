# Use a slim Python image as the base
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Install git and build tools (for editable install and any compiled deps)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Clone the PurpleLlama repository (shallow clone for speed)
RUN git clone --depth 1 https://github.com/anugram/PurpleLlama.git

# Set working directory to LlamaFirewall
WORKDIR /app/PurpleLlama/LlamaFirewall

# Install the llamafirewall package in editable mode
RUN pip install --upgrade pip && \
    pip install -e .

# (Optional) Set a non-root user for security
# RUN useradd -m appuser
# USER appuser

# Default command (replace with your actual entrypoint if needed)
CMD ["python3"]
