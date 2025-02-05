echo "Setting virtualenv"
python3 -m venv venv-lin
echo "Activating virtualenv"
. venv-lin/bin/activate
echo "Installing requirements"
python -m pip install -Ur requirements.txt
echo "Installing pyinstaller"
python -m pip install -U pyinstaller
echo "Building"
pyinstaller -y --contents-directory libs --distpath dist-lin --workpath build-lin ./mineportproxy.py
echo "Making dist-lin/mineportproxy-linux.tar.xz"
cd dist-lin
rm mineportproxy-linux.tar.xz 2> /dev/null
tar -cJf mineportproxy-linux.tar.xz mineportproxy
echo "Done"
