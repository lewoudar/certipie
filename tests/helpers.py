import shutil
import zipfile
from pathlib import Path


def assert_zipfile(content: bytes, tmp_path: Path, filename_prefix='id_rsa') -> None:
    filename = tmp_path / 'file.zip'
    with filename.open('wb') as archive:
        archive.write(content)

    with zipfile.ZipFile(filename) as my_zip:
        for file in my_zip.namelist():
            my_zip.extract(file)
            file_path = Path(file)

            assert file_path.stem == filename_prefix
            if 'pub' in file:
                assert file_path.read_text().startswith('-----BEGIN PUBLIC KEY-----')
            else:
                assert file_path.read_text().startswith('-----BEGIN RSA PRIVATE KEY-----')

    shutil.rmtree(file_path.parents[1])
