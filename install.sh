chmod +x run.sh
export PATH="$PATH:/root/tierzerocode"
sudo ln -s /root/tierzerocode/manage.py manage
cp tierzerocode.service /etc/systemd/system/tierzerocode.service
systemctl enable tierzerocode.service