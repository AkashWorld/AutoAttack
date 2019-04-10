set +
BASEDIR=$(dirname "$0")
sudo apt-get install build-essential
sudo apt-get install nasm
sudo apt-get install python3
sudo apt-get install python3-pip
pip3 install virtualenv
pip3 install -r $BASEDIR/requirements.txt
python3 -m virtualenv venv
set -
