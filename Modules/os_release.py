import Modules.commons as commons
import Modules.constants as constants

NAME_FIELD = 'NAME='
VERSION_FIELD = 'VERSION_ID='
PRETTY_NAME_FIELD = 'PRETTY_NAME='
BASIC_COLOR = '\033[00m'
EXPLANATION = '\033[90m'


# This function receives the requested field information.
def get_field(information_fields, debug, container_name):
    os_release_path = '/etc/os-release'
    release_information = commons.file_content(os_release_path, debug, container_name)
    host_information = ''
    for field in release_information:
        if 'Distribution' in information_fields and field.startswith(NAME_FIELD):
            distribution = field.split('=')[constants.END][constants.FIRST:constants.END].split(' ')[constants.START]
            host_information += distribution
        elif 'Version' in information_fields and field.startswith(VERSION_FIELD):
            if host_information:
                host_information += ' '
            host_version = field.split('=')[constants.FIRST]
            if host_version.startswith('"') and host_version.endswith('"'):
                host_version = host_version[constants.FIRST:constants.END]
            host_information += host_version
        elif 'Sid' in information_fields and field.startswith(PRETTY_NAME_FIELD):
            if field.split('=')[constants.FIRST].__contains__('sid'):
                if host_information:
                    host_information += ' '
                host_information += ' unstable'
    return host_information
