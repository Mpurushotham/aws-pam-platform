# Containerized PAM operational tooling (discovery, rotation, compliance, audit).
# Build: docker build -f docker/Dockerfile -t pam-tooling .
# Run:   docker run --rm -e AWS_PROFILE=... -v ~/.aws:/home/pam/.aws:ro pam-tooling \
#          compliance_auditor.py --frameworks cis
FROM python:3.9-slim AS base

# Non-root runtime user.
RUN useradd --create-home --uid 10001 pam

WORKDIR /app
COPY scripts/python/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/python/ ./
RUN chown -R pam:pam /app

USER pam
ENV PYTHONUNBUFFERED=1 \
    PAM_LOG_LEVEL=INFO \
    PATH="/app:${PATH}"

# Default to showing the discovery help; override the command as needed.
ENTRYPOINT ["python"]
CMD ["pam_privileged_account_discovery.py", "--help"]
