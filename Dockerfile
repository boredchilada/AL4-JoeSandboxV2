FROM cccs/assemblyline-v4-service-base:stable

# Python path to the service class
ENV SERVICE_PATH joesandbox.JoeSandboxV2

# Install required dependencies
USER root

# Install system dependencies needed for building Python packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    python3-dev \
    libffi-dev \
    libfuzzy-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && rm -rf ~/.cache/pip

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Set proper permissions
RUN chown -R assemblyline:assemblyline /opt/al_service/
RUN chmod -R 755 /opt/al_service/

# Switch to assemblyline user
USER assemblyline