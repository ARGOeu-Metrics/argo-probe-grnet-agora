from setuptools import setup
import glob

NAME='nagios-plugin-grnet-agora'
NAGIOSPLUGINS='/usr/libexec/argo-monitoring/probes/grnet-agora'

def get_ver():
    try:
        for line in open(NAME+'.spec'):
            if "Version:" in line:
                return line.split()[1]
    except IOError:
        print "Make sure that %s is in directory"  % (NAME+'.spec')
        sys.exit(1)

def data_files():
    import os
    if (not os.path.isdir('/usr/libexec/')):
        return []
    return [(NAGIOSPLUGINS, glob.glob('src/*'))]

setup(name=NAME,
      version=get_ver(),
      license='AGPL 3.0',
      author='GRNET',
      author_email='angelakis@grnet.gr',
      description='Package includes probes for Agora',
      platforms='noarch',
      long_description='''
      This package includes probes for Agora.
      Currently it supports the following components:
        - Agora Health Check
      ''',
      url='https://eosc.agora.grnet.gr/',
      data_files=data_files(),
      packages=['agora_probes'],
      package_dir={'agora_probes': 'modules/'},
      install_requires=[
          'requests>=2.19.1',
      ],
)
