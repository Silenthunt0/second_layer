from setuptools import setup

APP = ['main.py']
OPTIONS = {
    'argv_emulation': False,
    'includes': ['tkinter'],
    'packages': ['cryptography'],
    'plist': {
        'CFBundleName': 'Second Layer',
        'CFBundleIdentifier': 'space.silenthunt.secondlayer',
        'CFBundleVersion': '0.1.0',
        'CFBundleShortVersionString': '0.1.0',
    },
}

setup(
    app=APP,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
