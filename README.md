# VT Checker ![Python](https://img.shields.io/badge/-Python-black?style=flat&logo=Python) ![version](https://img.shields.io/badge/version-v1.0-blueviolet) ![platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-green)

VT Checker is a python script to help you check bulk of hashes against multiple security engines also has the ability to reanalyse the file
in order to give you the latest security engines results.

## Table of contents
* [General info](#general-info)
* [Libraries](#libraries)
* [Features](#Features)
* [Setup](#setup)
* [Test](#test)

## General info
VT Checker: Enables you check bulk of different types of hashes with the most recent results, also you can feed it with
the name of your security products and it will ignore hashes if it was detected by your security controls in order not to block them
in your environment.



## Libraries
Project is created with:

* requests
* time
* python 3.6 or higher.

## Features

* The Script can deal with most famous types of Hashes:
  * MD5
  * SHA1
  * SHA256
* Proxy compitable so it can be used by security teams in corporates, also you can disable proxy.
* Configured to handle two security devices (most probably Anti-Virus, EDR).
* Ability to reanalyze the hash to get the most recent scan results.

## Setup
To run this project, install all the required libraries first, then confiure the python script as follows:

* Update **x-apikey** variable with your VT API Key.
* 
* Update the following variables with your security controls in your evironment:
  * av_engine_1 = 1st (AV or EDR)
  * av_engine_2 = 2nd (AV or EDR)
* Then, Run the script using the following command:

```
$ python vt.py
```

## Test

Tested with a set of Hashes:

```
C:\Users\<current user>\Desktop> python vt.py
Welcome to 

 █████   █████ ███████████      █████████  █████                        █████                        
░░███   ░░███ ░█░░░███░░░█     ███░░░░░███░░███                        ░░███                         
 ░███    ░███ ░   ░███  ░     ███     ░░░  ░███████    ██████   ██████  ░███ █████  ██████  ████████ 
 ░███    ░███     ░███       ░███          ░███░░███  ███░░███ ███░░███ ░███░░███  ███░░███░░███░░███
 ░░███   ███      ░███       ░███          ░███ ░███ ░███████ ░███ ░░░  ░██████░  ░███████  ░███ ░░░ 
  ░░░█████░       ░███       ░░███     ███ ░███ ░███ ░███░░░  ░███  ███ ░███░░███ ░███░░░   ░███     
    ░░███         █████       ░░█████████  ████ █████░░██████ ░░██████  ████ █████░░██████  █████    
     ░░░         ░░░░░         ░░░░░░░░░  ░░░░ ░░░░░  ░░░░░░   ░░░░░░  ░░░░ ░░░░░  ░░░░░░  ░░░░░     
                                                                                       Version: 1.0
                                                                                 By: Mohab El-Banna
                                                                                 Github: Mouhab-dev 
                                                                           
```
