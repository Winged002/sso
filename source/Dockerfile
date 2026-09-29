FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8003
CMD ["gunicorn","-w","2","--threads","4","--timeout","60","-b","0.0.0.0:8003","syntal_sso:create_app()"]
