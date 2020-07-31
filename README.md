# Agora Probes

This repository contains Nagios plugins to check availability of Agora Catalogue Service.

Currently it supports the following probes:
 - Agora Health Check

## Requirements
- Python 2.7
- Pip

## Installation
Install the requirements using pip (preferably in a virtualenv):
```
$ pip install -r requirements.txt
```

Then use setup.py to install the program:
```
$ python setup.py install
```

## Usage
```
checkhealth [-h] -U URL [-v] [-t TIMEOUT] [-u USERNAME]
            [-p PASSWORD] [-i]


optional arguments:
  -h, --help            show this help message and exit
  -U URL, --url URL
                        Agora's url
  -v, --verbose         verbose output
  -t TIMEOUT, --timeout TIMEOUT
                        timeout for requests, default=180
  -u USERNAME, --username USERNAME
                        username
  -p PASSWORD, --password PASSWORD
                        password
  -i, --insecure        ignore SSL errors
```

## What the probes do

### Agora Health Check

Agora Health Check does the following:

- Given the username and password it will try to login and retrieve the respective auth token
- Check if /api/v2/resources is responding properly and can be accessed with the previously retrieved auth token


The probe returns exit codes and responses according to Nagios Plugins Specifications.

## Running the tests
After installing requirements.txt, you can run the tests from the project directory like this:
```
$ python -m unittest discover
```

## Copyright and license

Copyright (C) 2018 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see [http://www.gnu.org/licenses/]([http://www.gnu.org/licenses/).

## Funding
The work represented by this software was partially funded by

- EOSC-Hub project European Union (EU) Horizon 2020 program under Grant number 77753642.
- EUDAT2020 European Union’s H2020 Program under Contract No. 654065.
- EUDAT Framework Programme 7 under Contract No. 283304.
