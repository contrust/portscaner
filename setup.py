from setuptools import setup, find_packages

setup(
    name='portscaner',
    version='1.0.0',
    packages=find_packages(include=['portscaner', 'portscaner.*']),
    entry_points={
        'console_scripts': [
            'portscan = portscaner.__main__:main',
        ]
    }
)
