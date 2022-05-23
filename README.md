# VT Checker ![Python](https://img.shields.io/badge/-Python-black?style=flat&logo=Python) ![version](https://img.shields.io/badge/version-v1.0-blueviolet) ![platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-green)

VT Checker is a python script to help you check bulk of hashes against multiple security engines also has the ability to reanalyse the file
in order to give you the latest security engines results.

## Table of contents
* [General info](#general-info)
* [Libraries](#libraries)
* [Setup](#setup)
* [Test](#test)

## General info
VT Checker: Enables you check bulk of different types of hashes with the most recent results, also you can feed it with
the name of your security products and it will ignore hashes if it was detected by your security controls.

The Script can deal with all types of Hashes:
* MD5
* SHA1
* SHA256

## Libraries
Project is created with:
* base64.
* json.
* requests.
* getpass.
* csv.
* re.
* pandas.
* python 3.6 or higher.

## Setup
To run this project, install all the required libraries first then confiure the python script as follows:

* Update the **host** variable with your Qradar's IP Address.
* Configure the **search_period** variable to your liking, please follow qradar's documentation in order not to break the search query.
* Adjust **each search query** to your corresponding field name in your environment.
* Then, Run the script using the following command:

```
$ python qradar_iocs.py
```

## Test

Tested with a set of IOCs:

```
C:\Users\<current user>\Desktop> python qradar_iocs.py
Welcome to 
 __   __        __        __         __   __   __      __   ___ ___  ___  __  ___    __       
/  \ |__)  /\  |  \  /\  |__) .   | /  \ /  ` /__`    |  \ |__   |  |__  /  `  |  | /  \ |\ |
\__X |  \ /~~\ |__/ /~~\ |  \ .   | \__/ \__, .__/    |__/ |___  |  |___ \__,  |  | \__/ | \|
                                                                                 Version: 1.0
                                                                           By: Mohab El-Banna
                                                                           Github: Mouhab-dev
                                                                           
Password:
```




