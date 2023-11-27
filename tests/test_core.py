from pathlib import Path
from typing import Optional

import idna
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate, CertificateSigningRequest, DNSName, IPAddress, RFC822Name
from pydantic import ValidationError

from certipie.core import (
    create_auto_certificate,
    create_csr,
    create_private_key,
    get_public_key_from_private_key,
    normalize_alternative_name,
)
from tests.helpers import assert_pydantic_error


class TestCreatePrivateKey:
    """Tests function create_private_key"""

    @pytest.mark.parametrize('name', [b'foo', 4])
    def test_should_raise_error_when_filename_is_not_a_string(self, name):
        with pytest.raises(ValidationError) as exc_info:
            create_private_key(name)  # type: ignore

        assert_pydantic_error(exc_info.value, 'string_type')

    def test_should_raise_error_when_filename_length_is_less_than_1(self):
        with pytest.raises(ValidationError) as exc_info:
            create_private_key('')

        assert_pydantic_error(exc_info.value, 'string_too_short')

    def test_should_raise_error_when_key_size_is_not_an_integer(self):
        with pytest.raises(ValidationError) as exc_info:
            create_private_key('foo.pem', 'far')  # type: ignore

        assert_pydantic_error(exc_info.value, 'int_parsing')

    def test_should_raise_error_when_key_size_is_less_than_512(self):
        with pytest.raises(ValidationError) as exc_info:
            create_private_key('foo.pem', 30)

        assert_pydantic_error(exc_info.value, 'greater_than_equal')

    @pytest.mark.parametrize('passphrase', [b'bla', 'bla', '', b''])
    def test_should_create_and_return_private_key_given_correct_input(self, tmp_path, passphrase):
        private_key = tmp_path / 'key.pem'
        key = create_private_key(f'{private_key}', passphrase=passphrase)
        assert private_key.is_file()
        assert private_key.read_text().startswith('-----BEGIN RSA PRIVATE KEY-----')
        assert isinstance(key, rsa.RSAPrivateKey)


class TestGetPublicKeyFromPrivateKey:
    """Tests function get_public_key_from_private_key"""

    def test_should_create_public_key_given_file_path_and_private_key(self, tmp_path, private_key):
        public_key = tmp_path / 'id_rsa.pub'
        private_key = load_pem_private_key(private_key.read_bytes(), b'passphrase')
        get_public_key_from_private_key(public_key, private_key)

        assert public_key.read_text().startswith('-----BEGIN PUBLIC KEY-----')


class TestCreateCsr:
    """Tests function create_csr"""

    # filename checks

    @pytest.mark.parametrize('name', [b'foo', 4])
    def test_should_raise_error_when_filename_is_not_a_string(self, name):
        with pytest.raises(ValidationError) as exc_info:
            create_csr(name, 'FR', 'Ile-de-France', 'Paris', 'organization', 'site.com')  # type: ignore

        assert_pydantic_error(exc_info.value, 'string_type')

    def test_should_raise_error_when_filename_length_is_less_than_1(self):
        with pytest.raises(ValidationError) as exc_info:
            create_csr('', 'FR', 'Ile-de-France', 'Paris', 'organization', 'site.com')  # type: ignore

        assert_pydantic_error(exc_info.value, 'string_too_short')

    # common parameter checks

    @pytest.mark.parametrize('argument', [{'country': 4}, {'state_or_province': 4}, {'city': 4}, {'organization': 4}])
    def test_should_raise_error_when_common_parameters_are_not_string(self, argument):
        arguments = {
            'country': 'FR',
            'state_or_province': 'Ile-de-France',
            'city': 'Paris',
            'organization': 'organization',
            'common_name': 'site.com',
        }
        arguments |= argument
        with pytest.raises(ValidationError) as exc_info:
            create_csr('csr.pem', **arguments)

        assert_pydantic_error(exc_info.value, 'string_type')

    # common_name checks

    def test_should_raise_error_when_common_name_is_not_a_string(self):
        with pytest.raises(ValidationError) as exc_info:
            create_csr('csr.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', 4)  # type: ignore

        assert_pydantic_error(exc_info.value, 'string_type')

    def test_should_raise_error_when_common_name_length_is_greater_than_255(self):
        with pytest.raises(ValidationError) as exc_info:
            create_csr('csr.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', 'a' * 256)

        assert_pydantic_error(exc_info.value, 'string_too_long')

    @pytest.mark.parametrize('domain_name', ['foo', 'foo.', 'foo.o'])
    def test_should_raise_value_error_when_common_name_is_not_a_valid_domain_name(self, domain_name):
        with pytest.raises(ValueError) as exc_info:
            create_csr('csr.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', domain_name)

        assert f'{domain_name} is not a valid domain name' == str(exc_info.value)

    # alternative_names checks

    def test_should_raise_value_error_when_alternative_name_length_is_more_than_255(self):
        with pytest.raises(ValidationError) as exc_info:
            create_csr('csr.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', 'site.com', ['foo.com', 'a' * 256])

        assert_pydantic_error(exc_info.value, 'string_too_long')

    def test_should_raise_value_error_when_alternative_name_is_not_a_valid_domain_name_1(self):
        alternative_names = ['foo.com', 'foo', 'pie.io', 'foo.']  # 2nd and 4th are incorrect
        with pytest.raises(ValueError) as exc_info:
            create_csr('csr.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', 'site.com', alternative_names)

        assert 'the following alternative names are not valid domain names: foo, foo.' == str(exc_info.value)

    def test_should_raise_value_error_when_alternative_name_is_not_a_valid_domain_name_2(self, mocker):
        alternative_name = 'foo.com'

        def fake_get_idn(domain: str) -> Optional[str]:
            if domain == alternative_name:
                raise idna.IDNAError
            else:
                return domain

        mocker.patch('certipie.core.get_idn_domain_name', side_effect=fake_get_idn)
        with pytest.raises(ValueError) as exc_info:
            create_csr('csr.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', 'site.com', [alternative_name])

        assert f'the following alternative names are not valid domain names: {alternative_name}' == str(exc_info.value)

    # private_key checks

    def test_should_raise_error_when_private_key_does_not_exist(self):
        with pytest.raises(ValidationError) as exc_info:
            # noinspection PyTypeChecker
            create_csr(
                'csr.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', 'site.com', private_key='unknown_file'
            )

        assert_pydantic_error(exc_info.value, 'path_not_file', 2)

    def test_should_raise_error_when_file_cannot_be_decoded(self, tmp_path):
        key = tmp_path / 'key.pem'
        key.write_text('fake key')

        with pytest.raises(ValueError):
            create_csr('csr.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', 'site.com', private_key=key)

    # correctness checks

    @pytest.mark.parametrize('domain', ['site.com', 'ドメイン.テスト'])
    def test_should_create_csr_without_given_alternative_names(self, tmp_path, private_key, domain):
        csr_path = tmp_path / 'csr.pem'
        csr = create_csr(
            f'{csr_path}',
            'FR',
            'Ile-de-France',
            'Paris',
            'organization',
            domain,
            private_key=private_key,
            passphrase=b'passphrase',
        )

        assert csr_path.is_file()
        assert csr_path.read_text().startswith('-----BEGIN CERTIFICATE REQUEST-----')
        assert isinstance(csr, CertificateSigningRequest)
        assert csr.subject.rfc4514_string() == f'CN={domain},O=organization,L=Paris,ST=Ile-de-France,C=FR'
        assert csr.attributes[0].value.endswith(idna.encode(domain))

    def test_should_create_csr_with_given_alternative_names(self, tmp_path, private_key):
        csr_path = tmp_path / 'csr.pem'
        alternative_names = ['site.com', '*.site.com', 'ドメイン.テスト']
        csr = create_csr(
            f'{csr_path}',
            'FR',
            'Ile-de-France',
            'Paris',
            'organization',
            'site.com',
            private_key=private_key,
            passphrase=b'passphrase',
            alternative_names=alternative_names,
        )

        assert csr_path.read_text().startswith('-----BEGIN CERTIFICATE REQUEST-----')
        assert csr.subject.rfc4514_string() == 'CN=site.com,O=organization,L=Paris,ST=Ile-de-France,C=FR'
        attribute_value = csr.attributes[0].value
        for alternative_name in alternative_names:
            # don't use the idna library which is much more strict with "*." ^^
            assert alternative_name.encode('idna') in attribute_value

    def test_should_create_csr_given_private_key_object(self, tmp_path, private_key):
        csr_path = tmp_path / 'csr.pem'
        domain = 'site.com'
        pk = load_pem_private_key(private_key.read_bytes(), b'passphrase')
        csr = create_csr(f'{csr_path}', 'FR', 'Ile-de-France', 'Paris', 'organization', domain, private_key=pk)

        assert csr_path.read_text().startswith('-----BEGIN CERTIFICATE REQUEST-----')
        assert csr.subject.rfc4514_string() == f'CN={domain},O=organization,L=Paris,ST=Ile-de-France,C=FR'
        assert csr.attributes[0].value.endswith(idna.encode(domain))

    def test_should_create_csr_given_private_key_and_no_passphrase(self, tmp_path):
        key = tmp_path / 'key.pem'
        csr_path = tmp_path / 'csr.pem'
        create_private_key(f'{key}')
        domain = 'site.com'
        csr = create_csr(f'{csr_path}', 'FR', 'Ile-de-France', 'Paris', 'organization', domain, private_key=key)

        assert csr_path.read_text().startswith('-----BEGIN CERTIFICATE REQUEST-----')
        assert csr.subject.rfc4514_string() == f'CN={domain},O=organization,L=Paris,ST=Ile-de-France,C=FR'

    def test_should_create_csr_without_giving_private_key(self, tmp_path, mocker):
        mocker.patch('uuid.uuid4', return_value='3c44c151-b6bb-4953-b058-9506e2065890')
        csr_path = tmp_path / 'csr.pem'
        domain = 'site.com'
        create_csr(f'{csr_path}', 'FR', 'Ile-de-France', 'Paris', 'organization', domain)
        private_key = tmp_path / '3c44c151-b6bb-4953-b058-9506e2065890-key.pem'

        assert private_key.is_file()
        assert private_key.read_text().startswith('-----BEGIN RSA PRIVATE KEY-----')
        assert csr_path.read_text().startswith('-----BEGIN CERTIFICATE REQUEST-----')


class TestNormalizeAlternativeName:
    """Tests function normalize_alternative_name"""

    # email checks

    def test_should_raise_value_error_when_email_is_not_idna_valid(self):
        with pytest.raises(ValueError):
            normalize_alternative_name('foo@ドメイン.テスト')

    @pytest.mark.parametrize('email', ['foo@bar.com', f'foo@{idna.encode("ドメイン.テスト").decode("ascii")}'])
    def test_should_return_valid_x509_object_given_correct_email(self, email):
        name = normalize_alternative_name(email)
        assert isinstance(name, RFC822Name)

    # ip address and network checks

    @pytest.mark.parametrize('value', ['127.0.0.1', '::1', '192.168.0.0/24'])
    def test_should_return_valid_x509_object_given_correct_ip_address_or_network(self, value):
        name = normalize_alternative_name(value)
        assert isinstance(name, IPAddress)

    # dns names checks

    @pytest.mark.parametrize('value', ['localhost', 'site.com', 'ドメイン.テスト'])
    def test_should_return_valid_x509_object_given_correct_dns_name(self, value):
        name = normalize_alternative_name(value)
        assert isinstance(name, DNSName)


class TestCreateAutoCertificate:
    """Tests function create_auto_certificate"""

    # filename checks

    @pytest.mark.parametrize('name', [b'foo', 4])
    def test_should_raise_error_when_filename_is_not_a_string(self, name):
        with pytest.raises(ValidationError) as exc_info:
            create_auto_certificate(name, 'FR', 'Ile-de-France', 'Paris', 'organization', 'site.com')  # type: ignore

        assert_pydantic_error(exc_info.value, 'string_type')

    def test_should_raise_error_when_filename_length_is_less_than_1(self):
        with pytest.raises(ValidationError) as exc_info:
            create_auto_certificate('', 'FR', 'Ile-de-France', 'Paris', 'organization', 'site.com')

        assert_pydantic_error(exc_info.value, 'string_too_short')

    # common parameter checks

    @pytest.mark.parametrize('argument', [{'country': 4}, {'state_or_province': 4}, {'city': 4}, {'organization': 4}])
    def test_should_raise_error_when_common_parameters_are_not_string(self, argument):
        arguments = {
            'country': 'FR',
            'state_or_province': 'Ile-de-France',
            'city': 'Paris',
            'organization': 'organization',
            'common_name': 'site.com',
        }
        arguments |= argument

        with pytest.raises(ValidationError) as exc_info:
            create_auto_certificate('cert.pem', **arguments)

        assert_pydantic_error(exc_info.value, 'string_type')

    # common_name checks

    def test_should_raise_error_when_common_name_is_not_a_string(self):
        with pytest.raises(ValidationError) as exc_info:
            create_auto_certificate('cert.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', 4)  # type: ignore

        assert_pydantic_error(exc_info.value, 'string_type')

    def test_should_raise_error_when_common_name_length_is_greater_than_255(self):
        with pytest.raises(ValidationError) as exc_info:
            create_auto_certificate('cert.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', 'a' * 256)

        assert_pydantic_error(exc_info.value, 'string_too_long')

    @pytest.mark.parametrize('domain_name', ['foo', 'foo.', 'foo.o'])
    def test_should_raise_value_error_when_common_name_is_not_a_valid_domain_name(self, domain_name):
        with pytest.raises(ValueError) as exc_info:
            create_auto_certificate('cert.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', domain_name)

        assert f'{domain_name} is not a valid domain name' == str(exc_info.value)

    # alternative_names check

    def test_should_raise_error_when_alternative_name_is_not_correct(self):
        alternative_names = ['localhost', 'a' * 256]  # 2nd is incorrect
        with pytest.raises(idna.IDNAError):
            create_auto_certificate(
                'cert.pem',
                'FR',
                'Ile-de-France',
                'Paris',
                'organization',
                'site.com',
                alternative_names=alternative_names,
            )

    # private_key checks

    def test_should_raise_error_when_private_key_does_not_exist(self):
        with pytest.raises(ValidationError) as exc_info:
            # noinspection PyTypeChecker
            create_auto_certificate(
                'cert.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', 'site.com', private_key='unknown_file'
            )

        assert_pydantic_error(exc_info.value, 'path_not_file', 2)

    def test_should_raise_error_when_file_cannot_be_decoded(self, tmp_path):
        key = tmp_path / 'key.pem'
        key.write_text('fake key')

        with pytest.raises(ValueError):
            create_auto_certificate(
                'cert.pem', 'FR', 'Ile-de-France', 'Paris', 'organization', 'site.com', private_key=key
            )

    # correctness checks

    @staticmethod
    def assert_certificate(cert_path: Path, cert: Certificate, common_name: str) -> None:
        assert isinstance(cert, Certificate)
        assert cert.subject.rfc4514_string() == f'CN={common_name},O=organization,L=Paris,ST=Ile-de-France,C=FR'
        assert cert_path.is_file()
        assert cert_path.read_text().startswith('-----BEGIN CERTIFICATE-----')

    def test_should_create_certificate_without_common_name_and_alternative_names(self, tmp_path, mocker):
        mocker.patch('uuid.uuid4', return_value='4babd8cf-b10a-44d2-96ac-ac6121c5cd61')
        cert_path = tmp_path / 'cert.pem'
        private_key_path = tmp_path / '4babd8cf-b10a-44d2-96ac-ac6121c5cd61-key.pem'
        cert = create_auto_certificate(f'{cert_path}', 'FR', 'Ile-de-France', 'Paris', 'organization')

        # certificate
        self.assert_certificate(cert_path, cert, 'localhost')

        # private_key
        assert private_key_path.is_file()
        assert private_key_path.read_text().startswith('-----BEGIN RSA PRIVATE KEY-----')

    def test_should_create_certificate_without_alternative_names(self, tmp_path):
        cert_path = tmp_path / 'cert.pem'
        domain = 'site.com'
        cert = create_auto_certificate(f'{cert_path}', 'FR', 'Ile-de-France', 'Paris', 'organization', domain)

        self.assert_certificate(cert_path, cert, domain)

    def test_should_create_certificate_given_alternative_names(self, tmp_path):
        domain = 'site.com'
        alternative_names = ['site.com', '*.site.com', '1.1.1.1', '::1', 'foo@email.com']
        cert_path = tmp_path / 'cert.pem'
        cert = create_auto_certificate(
            f'{cert_path}', 'FR', 'Ile-de-France', 'Paris', 'organization', domain, alternative_names=alternative_names
        )

        self.assert_certificate(cert_path, cert, domain)

    @pytest.mark.parametrize('give_file', [True, False])
    def test_should_create_certificate_given_private_key(self, tmp_path, private_key, give_file):
        domain = 'site.com'
        cert_path = tmp_path / 'cert.pem'
        passphrase = b'passphrase'
        if give_file:
            private_key = f'{private_key}'
        else:
            private_key = load_pem_private_key(private_key.read_bytes(), passphrase)

        cert = create_auto_certificate(
            f'{cert_path}',
            'FR',
            'Ile-de-France',
            'Paris',
            'organization',
            domain,
            private_key=private_key,
            passphrase=passphrase,
        )

        self.assert_certificate(cert_path, cert, domain)

    def test_should_create_certificate_given_private_key_and_no_passphrase(self, tmp_path):
        domain = 'site.com'
        key = tmp_path / 'key.pem'
        cert_path = tmp_path / 'cert.pem'
        create_private_key(f'{key}')

        cert = create_auto_certificate(
            f'{cert_path}', 'FR', 'Ile-de-France', 'Paris', 'organization', domain, private_key=key
        )

        self.assert_certificate(cert_path, cert, domain)
