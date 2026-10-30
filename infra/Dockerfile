FROM python:3.12-slim
WORKDIR /workspace
COPY packages/contracts /workspace/packages/contracts
COPY apps/api /workspace/apps/api
COPY infra/phase1-requirements.lock.txt /workspace/requirements.txt
RUN pip install --no-cache-dir -r /workspace/requirements.txt /workspace/packages/contracts /workspace/apps/api
RUN useradd --create-home cisguard
USER cisguard
EXPOSE 8000
CMD ["uvicorn", "cisguard_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
