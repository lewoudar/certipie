import os
import shutil

import nox

nox.options.reuse_existing_virtualenvs = True

PYTHON_VERSIONS = ['3.9', '3.10']
CI_ENVIRONMENT = 'GITHUB_ACTIONS' in os.environ


@nox.session(python=PYTHON_VERSIONS[-1])
def lint(session):
    """Performs pep8 and security checks."""
    source_code = 'certipie'
    session.install('flake8==4.0.1', 'bandit==1.7.2')
    session.run('flake8', source_code)
    session.run('bandit', '-r', source_code)


@nox.session(python=PYTHON_VERSIONS)
def tests(session):
    """Runs the test suite."""
    session.install('poetry>=1.0.0,<2.0.0')
    session.run('poetry', 'install')
    session.run('pytest')


@nox.session(python=False)
def deploy(session):
    """
    Deploys on pypi.
    """
    session.install('poetry>=1.0.0,<2.0.0')
    if 'POETRY_PYPI_TOKEN_PYPI' not in os.environ:
        session.error('you must specify your pypi token api to deploy your package')

    session.run('poetry', 'publish', '--build')


@nox.session(python=False, name='clean-nox')
def clean_nox(_):
    """
    Clean your nox environment.
    This is useful when running tests on a local machine, since nox takes a bit of memory, you can clean up if you want.
    """
    shutil.rmtree('.nox', ignore_errors=True)
