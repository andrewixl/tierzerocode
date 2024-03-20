ip=$(ifconfig ens160 | awk '/inet / {print $2}')
source venv/bin/activate
python3 manage.py runserver $ip:8000