import pytest
from pydantic import ValidationError, BaseModel

from certipie.api.schemas import DomainName


class MyDomain(BaseModel):
    domain: DomainName


class TestDomainName:
    """Test DomainName pydantic model"""

    @pytest.mark.parametrize('value', ['4', 'foo'])
    def test_should_raise_error_if_value_is_not_a_domain_name(self, value):
        with pytest.raises(ValidationError) as exc_info:
            MyDomain(domain=value)

        message = str(exc_info.value)
        assert 'domain' in message
        assert 'not a valid domain name' in message

    @pytest.mark.parametrize('value', ['foo.com', '*.foo.com', 'ドメイン.テスト'])
    def test_should_not_raise_error_when_value_is_correct(self, value):
        d = MyDomain(domain=value)
        assert d.domain == value
