#!/usr/bin/env python


from setuptools import setup

setup (
    name='pyras',
    version='1.0b2',
    description='Python Remote Access Server',
    author='The Test People',
    author_email='tony.simpson@thetestpeople.com',
    maintainer='Tony Simpson',
    license='MIT',
    packages=['pyras'],
    install_requires=['paramiko>=1.7.7','docopt>=0.5.0','ptools>=1.0b2'],
    long_description=open('README').read(),
    entry_points=dict(console_scripts=['pyras-serve=pyras:serve_main', 'pyras-genauth=pyras:genauth_main']),
)

