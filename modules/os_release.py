"""
Support for modules which written for avoiding repetitive code.
"""
from modules import commons, constants

NAME_FIELD = 'NAME='
VERSION_FIELD = 'VERSION_ID='
PRETTY_NAME_FIELD = 'PRETTY_NAME='
BASIC_COLOR = '\033[00m'
EXPLANATION = '\033[90m'


def get_field(information_fields, debug, container_name):
    """This function receives the requested field information."""
    os_release_path = '/etc/os-release'
    release_information = commons.file_content(os_release_path, debug, container_name)
    host_information = ''
    if release_information:
        for field in release_information:
            if 'Distribution' in information_fields and field.startswith(NAME_FIELD):
                distribution = field.split('=')[constants.END][constants.FIRST:constants.END]
                distribution = distribution.split(' ')[constants.START]
                if distribution == 'Debian' and field.endswith('sid"'):
                    return 'Debian unstable'
                host_information += distribution
            elif 'Version' in information_fields and field.startswith(VERSION_FIELD):
                if host_information:
                    host_information += ' '
                host_version = field.split('=')[constants.FIRST]
                if host_version.endswith('\n'):
                    host_version = host_version[:constants.END]
                if host_version.startswith('"') and host_version.endswith('"'):
                    host_version = host_version[constants.FIRST:constants.END]
                host_information += host_version
    return host_information
