FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt requirements-lock.txt ./
RUN pip install --no-cache-dir -r requirements-lock.txt && useradd --uid 10001 --create-home syntal
COPY --chown=10001:10001 . .
USER 10001:10001
EXPOSE 8003
CMD ["gunicorn","-w","2","--threads","4","--timeout","60","-b","0.0.0.0:8003","syntal_sso:create_app()"]
