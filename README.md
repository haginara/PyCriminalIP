# CriminalIP library for Pyhton(unofficial)

## Installation
- Install from git
```
git clone https://github.com/haginara/PyCriminalIP.git
cd PyCriminalIP
python setup.py install
```

- Install from pypi
```
pip install pycriminalip
```

## How-to-Use
### Prepare the API Key from Criminalip.io

### Import classes and create an objects
```
import typing
from criminalip import CriminalIP

ip = IP('api_key_from_criminalip_io')
ip_data: dict[str, typing.Any] = ip.data('aispera.com')
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
