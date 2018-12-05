from setuptools import setup, find_packages

from django_auth_adfs import __version__

with open('README.rst') as readme_file:
    readme = readme_file.read()
with open('CHANGELOG.rst') as changelog_file:
    changelog = changelog_file.read()

setup(
    name='django-auth-adfs',
    version=__version__,
    packages=find_packages(),
    author='Joris Beckers',
    author_email='joris.beckers@gmail.com',
    url="https://github.com/jobec/django-auth-adfs",
    download_url="https://pypi.python.org/pypi/django-auth-adfs",
    description='A Django authentication backend for Microsoft ADFS and AzureAD',
    long_description=readme + '\n\n' + changelog,
    license="BSD",
    keywords='django authentication adfs oauth2',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django :: 1.9',
        'Framework :: Django :: 1.10',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 2.1',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Internet :: WWW/HTTP :: WSGI',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Development Status :: 5 - Production/Stable',
    ],
    install_requires=[
        'pyjwt >= 1.0.1',
        'cryptography>=1.7',
        'django >= 1.8',
        'requests',
    ],
    tests_require=[
        "responses",
        "mock",
        "cryptography",
        "coverage",
        "tox",
        "djangorestframework",
    ],
    zip_safe=False,
)
