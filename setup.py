from setuptools import setup, find_packages
with open("README.md", 'r') as f: long_desc = f.read()
setup(name='pwnscripts',
      version='0.1.0',
      description='Simple pwntools QoL scripts',
      long_description=long_desc,
      long_description_content_type='text/markdown',
      author='152334H',
      author_email='54623771+152334H@users.noreply.github.com',
      license='GPL3',
      url='https://github.com/152334H/pwnscripts',
      packages=find_packages(),
      install_requires=['pwntools']
)
