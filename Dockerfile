# base image
FROM python:3.12.2

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Mounts the application code to the image
COPY . /tierzerocode

# where your code lives
WORKDIR /tierzerocode

# install dependencies
RUN pip install --upgrade pip

# Allows docker to cache installed dependencies between builds
RUN pip install -r requirements.txt

# migrate database
CMD python manage.py migrate
CMD python manage.py collectstatic --noinput

# port where the Django app runs
EXPOSE 8000

# start server
CMD ["gunicorn","--bind",":8000","--workers","3","tierzerocode.wsgi:application"]