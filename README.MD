###
NOTE. This project comes in two parts. The buffer generation, and the ROP generation. The buffer generation code is in the master branch and works on 64 bit machines. The ROP generation is in the second (AngrExperiments) branch. Please check both for grading.
###

# AutoAttack - GDBad

This software generates control flow exploits for binaries with buffers that facilitate memory corruption.

## Getting Started



### Prerequisites
This project is tested on x86-64 CPUs. The OS used is Linux 4.15 - 5.01, Ubuntu 18.04 LTS.  
A guide to install the softwares listed below is given in the installing section.  
The list of software used:  
python3  
pip3  
virtualenv  
angr  
g++  
gcc  
nasm  




### Installing
The easiest way to install most of these software is to run the setup.sh script in the root directory.  
```
chmod +x setup.sh
source setup.sh
```
The required software for this project:
* **Python3**
* **Pip3**
```
sudo apt-get install python3
sudo apt-get install python3-pip
```
* **virtualenv**
```
pip3 install virtualenv
```
With virtualenv installed, you must create a venv directory with your virtual environment.
```
python3 -m virtualenv env
```
To activate the environment, run the following script:
```
sudo source venv/bin/activate
```
* **angr**
Easiest way to install the required python packages is to run the following command while in
the virtual environment.
```
pip3 install -r requirements.txt
```
* **Standard build tools**
```
sudo apt-get install build-essential
```
```
sudo apt-get install nasm
```

## Authors

***TEAM GDBad***
* **Khalid Akash**
* **Brandon Smith**
* **Joey Bingham**
