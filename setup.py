import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.md')) as f:
    README = f.read()

requires = [
      'tornado',
      'requests',
      "pytest",
      "SQLalchemy",
      'zope.sqlalchemy',
      'PyMysql'
    ]

setup(name='Cockoo',
      version='0.5.0',
      description='Cuckoo Apple push notifications server',
      long_description=README,
      classifiers=[
        "Programming Language :: Python",
        "Framework :: Autobahn",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        ],
      author='Biokod Lab Sp. z o.o.',
      author_email='biuro@biokod.pl',
      url='',
      keywords='web wsgi bfg application',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      test_suite='cuckoo-test',
      install_requires=requires,
      )