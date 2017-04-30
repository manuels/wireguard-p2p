from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='wireguard-p2p',

    version='0.1.3',

    description='A tool for setting up WireGuard connections from peer to peer.',
    long_description=long_description,

    url='https://github.com/manuels/wireguard-p2p',

    author='Manuel Schoelling',
    author_email='manuel.schoelling@gmx.de',

    license='GPL',

    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: System Administrators',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Communications',
        'Topic :: System :: Networking',

        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],

    keywords='wireguard peer-to-peer p2p',

    packages=find_packages(exclude=['contrib', 'docs', 'tests']),

    install_requires=['docopt', 'PyNaCl', 'termcolor'],

    entry_points={
        'console_scripts': [
            'wg-p2p=wg_p2p.main:main',
        ],
    },
)

