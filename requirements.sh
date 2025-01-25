#!/bin/bash
clear
echo -e '\033[0;32m' "++++++++++ INSTALLING NIM ++++++++++" '\033[0m'
echo " "
if [ ! -f /home/$USER/.nimble/bin/nim ]; then
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
sudo echo "export PATH="/home/$USER/.nimble/bin:$PATH"" >> ~/.zshrc
echo " "
echo -e '\033[0;32m' "++++ done +++++"'\033[0m'
else
echo -e '\033[0;32m' "+++++ you already have nim installed in /home/$USER/.nimble/bin/nim PATH ++++" '\033[0m'
fi

echo " " 
echo -e '\033[0;32m' "+++++++++++ downloading the program requirements ++++++++++" '\033[0m'
tools=( winim ptr_math nimcrypto times random net psutil strformat GetSyscallStub)
#echo ${tools[*]}
for tools in ${tools[*]}; do nimble install $tools ; done

