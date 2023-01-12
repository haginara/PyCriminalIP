from criminalip.CriminalIP import IP
from criminalip.CriminalIP import Banner
from criminalip.CriminalIP import Domain


def test_api_urls():
    ip = IP(api_key='test')
    assert ip.api_url == "https://api.criminalip.io/v1/ip/"

    domain = Domain(api_key='test')
    assert domain.api_url == "https://api.criminalip.io/v1/domain/"

    banner = Banner(api_key='test')
    assert banner.api_url == "https://api.criminalip.io/v1/banner/"