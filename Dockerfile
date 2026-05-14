FROM python:3.11-slim

WORKDIR /app

# No system packages needed for pillow-heif: the manylinux wheel bundles
# libheif, libde265, libaom, and libx265. We also prefer stdlib urllib over
# curl for the healthcheck to keep the image minimal.

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source (tests, .cursor, data, and test-cards excluded via .dockerignore)
COPY app.py main.py session.py vcard_builder.py google_csv_builder.py ./
COPY baml_client/ baml_client/
COPY baml_src/ baml_src/
COPY validation/ validation/
COPY static/ static/
COPY templates/ templates/

# Run as a non-root user
RUN useradd --no-create-home --shell /bin/false appuser
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
