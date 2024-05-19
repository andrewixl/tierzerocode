# base image
FROM python:3.12.2
# setup enviornment variable
ENV DockerHOME=/home/app/tzc

# set work directory
RUN mkdir -p $DockerHOME

# where your code lives
WORKDIR $DockerHOME

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
RUN pip install --upgrade pip

# copy whole project to your docker home directory
COPY . $DockerHOME
# run this command to install all dependencies
RUN pip install -r requirements.txt
RUN pip install gunicorn
# port where the Django app runs
EXPOSE 8000
# migrate database
CMD python manage.py migrate
CMD python manage.py collectstatic --noinput
# start server
CMD ["gunicorn","--bind", ":8000", "tzc.wsgi:application"]