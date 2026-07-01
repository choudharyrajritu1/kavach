FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --create-home --uid 10001 kavach && chown -R kavach:kavach /app
USER kavach

EXPOSE 8000
CMD ["uvicorn", "kavach.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
