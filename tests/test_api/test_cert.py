import pytest

from certipie.core import create_private_key
from tests.helpers import assert_private_key, assert_csr


class TestPrivateKey:
    """Tests POST /certs/private-key"""

    def test_should_return_error_when_key_size_is_not_convertible_to_int(self, client):
        r = client.post('/certs/private-key', json={'key_size': 'foo'})

        assert r.status_code == 422
        assert r.json() == {
            'detail': [
                {
                    'loc': ['body', 'key_size'],
                    'msg': 'value is not a valid integer',
                    'type': 'type_error.integer'
                }
            ]
        }

    def test_should_return_error_when_key_size_is_less_than_512(self, client):
        r = client.post('/certs/private-key', json={'key_size': 40})

        assert r.status_code == 422
        assert r.json() == {
            'detail': [
                {
                    'loc': ['body', 'key_size'],
                    'msg': 'ensure this value is greater than or equal to 512',
                    'type': 'value_error.number.not_ge',
                    'ctx': {'limit_value': 512}
                }
            ]
        }

    def test_should_create_pair_of_keys_without_payload(self, client, tmp_path, unzip_file):
        r = client.post('/certs/private-key')

        assert r.status_code == 200
        assert r.headers['content-type'] == 'application/zip'

        paths = unzip_file(r.content, tmp_path)
        assert_private_key(paths)

    @pytest.mark.parametrize(('payload', 'prefix'), [
        ({'filename_prefix': 'foo'}, 'foo'),
        ({'key_size': 1024}, 'id_rsa'),
        ({'passphrase': 'secret', 'filename_prefix': 'top_secret'}, 'top_secret')
    ])
    def test_should_create_pair_of_keys_with_payload(self, client, tmp_path, unzip_file, payload, prefix):
        r = client.post('/certs/private-key', json=payload)

        assert r.status_code == 200
        assert r.headers['content-type'] == 'application/zip'

        paths = unzip_file(r.content, tmp_path)
        assert_private_key(paths, prefix=prefix)


@pytest.fixture()
def base_payload() -> dict:
    return {
        'filename_prefix': 'my_csr',
        'country': 'FR',
        'state_or_province': 'Ile-de-France',
        'city': 'Paris',
        'organization': 'Organization Inc.',
        'common_name': 'site.com',
        'alternative_names': ['site.com', 'foo.com', '*.bar.com']
    }


class TestCsr:
    """Tests route POST /certs/csr"""

    @pytest.mark.parametrize('field', [
        'state_or_province',
        'city',
        'organization'
    ])
    def test_should_return_error_when_mandatory_field_is_empty(self, client, base_payload, field):
        base_payload[field] = ''
        r = client.post('/certs/csr', data=base_payload)

        assert r.status_code == 422
        assert r.json() == {
            'detail': [
                {
                    'loc': ['body', field],
                    'msg': 'field required',
                    'type': 'value_error.missing'
                }
            ]
        }

    @pytest.mark.parametrize('country', ['C', 'CAM'])
    def test_should_return_error_when_country_has_a_length_different_to_two(self, client, base_payload, country):
        base_payload['country'] = country
        r = client.post('/certs/csr', data=base_payload)

        assert r.status_code == 422
        adjective = 'least' if country == 'C' else 'most'
        error_type = 'value_error.any_str.min_length' if country == 'C' else 'value_error.any_str.max_length'
        assert r.json() == {
            'detail': [
                {
                    'loc': ['body', 'country'],
                    'msg': f'ensure this value has at {adjective} 2 characters',
                    'type': error_type,
                    'ctx': {'limit_value': 2}
                }
            ]
        }

    @pytest.mark.parametrize('domain', ['4', 'foo'])
    def test_should_return_error_when_common_name_is_not_a_domain_name(self, client, base_payload, domain):
        base_payload['common_name'] = domain
        r = client.post('/certs/csr', data=base_payload)

        assert r.status_code == 422
        assert r.json() == {
            'detail': [
                {
                    'loc': ['body', 'common_name'],
                    'msg': 'not a valid domain name',
                    'type': 'value_error'
                }
            ]
        }

    @pytest.mark.parametrize('domain', ['4', 'foo'])
    def test_should_return_error_when_alternative_name_is_not_a_domain_name(self, client, base_payload, domain):
        base_payload['alternative_names'] = ['site.com', domain, 'foo.com']
        r = client.post('/certs/csr', data=base_payload)

        assert r.status_code == 422
        assert r.json() == {
            'detail': [
                {
                    'loc': ['body', 'alternative_names', 1],
                    'msg': 'not a valid domain name',
                    'type': 'value_error'
                }
            ]
        }

    def test_should_return_error_when_provided_private_key_is_incorrect(self, tmp_path, client, base_payload):
        fake_key = tmp_path / 'key.pem'
        fake_key.write_text('hello world!')

        with open(fake_key, 'rb') as f:
            r = client.post('/certs/csr', files={'private_key': f}, data=base_payload)

        assert r.status_code == 422

    @pytest.mark.parametrize('default_filename', [True, False])
    @pytest.mark.parametrize('default_alternative_names', [True, False])
    def test_should_return_zipfile_without_giving_private_key(
            self, tmp_path, client, unzip_file, base_payload, default_filename, default_alternative_names
    ):
        if default_filename:
            csr_prefix = 'csr'
            base_payload.pop('filename_prefix')
        else:
            csr_prefix = 'my_csr'
        if default_alternative_names:
            base_payload.pop('alternative_names')

        r = client.post('/certs/csr', data=base_payload)

        assert r.status_code == 200
        assert r.headers['content-type'] == 'application/zip'

        paths = unzip_file(r.content, tmp_path)
        assert_csr(paths, csr_prefix)

    def test_should_return_zipfile_with_given_private_key_and_passphrase(
            self, tmp_path, client, private_key, unzip_file, base_payload
    ):
        with open(private_key, 'rb') as f:
            base_payload['passphrase'] = 'passphrase'
            r = client.post('/certs/csr', files={'private_key': f}, data=base_payload)

        assert r.status_code == 200
        assert r.headers['content-type'] == 'application/zip'

        paths = unzip_file(r.content, tmp_path)
        assert len(paths) == 1
        assert_csr(paths, 'my_csr')

    def test_should_return_zipfile_with_given_private_key_and_no_passphrase(
            self, tmp_path, client, unzip_file, base_payload
    ):
        key = tmp_path / 'key.pem'
        create_private_key(f'{key}')

        with key.open('rb') as f:
            r = client.post('/certs/csr', files={'private_key': f}, data=base_payload)

        assert r.status_code == 200
        assert r.headers['content-type'] == 'application/zip'

        paths = unzip_file(r.content, tmp_path)
        assert len(paths) == 1
        assert_csr(paths, 'my_csr')
