""" Setup file.
"""
import os
from setuptools import setup, find_packages

setup(name='emokykla',
      version=0.1,
      description='emokykla',
      long_description='LDAP-based Identity Management Web service.',
      classifiers=[
          "Programming Language :: Python",
          "Framework :: Pylons",
          "Topic :: Internet :: WWW/HTTP",
          "Topic :: Internet :: WWW/HTTP :: WSGI :: Application"
      ],
      keywords="web services",
      author='',
      author_email='',
      url='',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'cornice',
          'waitress',
          'python-dateutil',
          'python3_ldap',
          'Sphinx',
          'pyramid_webassets',
          'webassets==0.9',
      ],
      dependency_links=[
          'https://github.com/sontek/pyramid_webassets/tarball/master#egg=pyramid_webassets-0.8',
      ],
      entry_points="""\
      [paste.app_factory]
      main = emokykla:main
      """,
      paster_plugins=['pyramid'],
      )
