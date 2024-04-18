# Author  : Team Google SS24
# Access instance using `docker exec -it teamgoogle-android-vulnerability-database-flask-app bash`

# Instantiate Ubuntu 20.04
FROM ubuntu:20.04
LABEL maintainer "Team Google SS24"
LABEL description="This is custom Docker Image for Team Google's android vulnerability database"

# Update Ubuntu Software repository
RUN apt update
RUN apt-get update -qq


# Add the Flask application and install requirements
RUN apt -y install python3-pip
RUN apt -y install vim
RUN mkdir /app
COPY . /app
WORKDIR /app
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Open ports, set environment variables, start gunicorn.
EXPOSE 8080 
ENV PORT 8080
ENV FLASK_ENV=production  
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
# ----------------------------------------------------- 
