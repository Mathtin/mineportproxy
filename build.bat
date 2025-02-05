echo "Setting virtualenv"
python -m venv venv-win
echo "Activating virtualenv"
call venv-win/Scripts/activate.bat
echo "Installing requirements"
python -m pip install -Ur requirements.txt
echo "Installing pyinstaller"
python -m pip install -U pyinstaller
echo "Building"
pyinstaller -y --uac-admin -i ./minecraft_icon.ico --contents-directory libs --distpath dist-win --workpath build-win ./mineportproxy.py
echo "Making dist-win/mineportproxy-windows.zip"
cd dist-win
del mineportproxy-windows.zip
powershell Compress-Archive mineportproxy mineportproxy-windows.zip
