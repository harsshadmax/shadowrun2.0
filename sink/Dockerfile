FROM python:3.11-slim
RUN pip install --no-cache-dir fastapi uvicorn
COPY app.py /app/app.py
WORKDIR /app
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9000", "--log-level", "warning"]
