# base image
FROM python:3.12.2

# where your code lives
WORKDIR /tierzerocode

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
RUN pip install --upgrade pip
# Allows docker to cache installed dependencies between builds
COPY requirements.txt /tierzerocode/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Mounts the application code to the image
COPY . /tierzerocode

# port where the Django app runs
EXPOSE 8000

# migrate database
CMD python manage.py migrate
CMD python manage.py collectstatic --noinput

# start server
CMD ["gunicorn","--config","gunicorn_config.py","tierzerocode.wsgi:application"]