# CriminalIP Pyhton library

## Installation
- Install from git
```
git clone https://github.com/haginara/PyCriminalIP.git
cd PyCriminalIP
python setup.py install
```

- Install from pypi (Not yet supported)
```
pip install pycriminalip
```

## How-to-Use
### Prepare the API Key from Criminalip.io

### Import classes and create an objects
```
from typing import Dict

from criminalip.CriminalIP import IP
from criminalip.CriminalIP import Banner
from criminalip.CriminalIP import Domain
from criminalip.CriminalIP import Exploit

ip = IP('api_key_from_criminalip_io')
ip_data: Dict[str, Any] = ip.data('aispera.com')
print(ip_data)
```

## Development
It requires `pipenv` to manage the requirements. And it also requires make command as optional
```
pipenv install
```

## Unit Testing
```
pipenv run pytest
# or
pipenv run python -m unittest tests.test_CriminalIP
```
