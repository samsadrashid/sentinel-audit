FROM python:3.12-slim
RUN useradd -m app
COPY . /app
USER app
HEALTHCHECK CMD python -c "print(1)"
CMD ["python", "/app/main.py"]
