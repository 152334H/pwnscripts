from setuptools import setup, find_packages
with open("README.md", 'r') as f: long_desc = f.read()
# Current effect: bundles everything in ./pwnscripts/. This excludes ./examples/.
setup(name='pwnscripts',
      version='0.3.0',
      description='Simple pwntools QoL scripts',
      long_description=long_desc,
      long_description_content_type='text/markdown',
      author='152334H',
      author_email='54623771+152334H@users.noreply.github.com',
      license='GPL3',
      url='https://github.com/152334H/pwnscripts',
      packages=find_packages(),
      install_requires=['pwntools'],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'Natural Language :: English',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: Python :: 3.8',
          'Topic :: Security',
          'Topic :: Software Development :: Debuggers',
          'Topic :: Utilities'
      ],
      python_requires='>=3.8'
)
