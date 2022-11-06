"""
Support for modules which written for avoiding repetitive code.
"""
from modules import constants, file_functions

NAME_FIELD = 'NAME='
VERSION_FIELD = 'VERSION_ID='
PRETTY_NAME_FIELD = 'PRETTY_NAME='


def get_field(information_fields, debug, container_name):
    """This function receives the requested field information."""
    os_release_path = '/etc/os-release'
    release_information = file_functions.file_content(os_release_path, debug, container_name)
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


def check_release(fixed, debug, container_name):
    """This function checks if the host release is affected according to the fixed os distributions and versions."""
    information_fields = ['Distribution', 'Version']
    host_information = get_field(information_fields, debug, container_name)
    if host_information.startswith('Debian'):
        information_fields = ['Distribution', 'Sid']
        host_information_debian = get_field(information_fields, debug, container_name)
        if host_information_debian.endswith('unstable'):
            host_information = host_information_debian
    if host_information == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    if host_information:
        print(constants.FULL_QUESTION_MESSAGE.format('Is os release affected?'))
        host_distribution = host_information.split(' ')[constants.START]
        if host_distribution not in constants.APT_DISTRIBUTIONS and \
                host_distribution not in constants.APT_DISTRIBUTIONS:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Can not determine'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected os releases: {list(fixed.keys())}\nYour os '
                                                            f'release: {host_distribution}\nThe os release you are '
                                                            f'running on is not supported'))
            return constants.UNSUPPORTED
        for fixed_release in fixed:
            if fixed_release == host_information:
                print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected os releases: {list(fixed.keys())}\nYour os'
                                                                f' release: {host_information}\nThe os release you are '
                                                                f'running on is potentially affected'))
                return fixed_release
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected os releases: {list(fixed.keys())}\nYour os '
                                                        f'release: {host_information}\nThe os release you are running '
                                                        f'on is not affected'))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, no distribution and '
                                                        'version values'))
    return ''
