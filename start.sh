#!/bin/sh
# Start script to run both gunicorn and rqworker

# Start gunicorn in the background
python -m gunicorn --bind 0.0.0.0:8000 --workers 3 tierzerocode.wsgi:application &

# Start rqworker in the background
python manage.py rqworker default --job-class django_tasks.backends.rq.Job &

# Wait for all background processes
wait

