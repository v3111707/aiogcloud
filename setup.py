from setuptools import setup
from os import environ

setup(name=environ['CI_PROJECT_NAME'],
      version=environ['CI_COMMIT_TAG'])
