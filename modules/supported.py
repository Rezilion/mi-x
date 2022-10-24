"""
Support for os and other modules which written for avoiding repetitive code.
"""
import os
from modules import run_command, constants

NAME_FIELD = 'NAME='
VERSION_FIELD = 'VERSION_ID='
ALPINE = 'alpine'


def file_content(file_path, debug, container_name):
    """This function checks returns the file's content if exists."""
    content = ''
    if container_name:
        cat_file_command = f'cat {file_path}'
        pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
        content = pipe_cat_file.stdout
        if content:
            content = content.split('\n')[:constants.END]
    else:
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = []
                    for line in file.readlines():
                        content.append(line[:constants.END])

            except PermissionError:
                cat_file_command = f'sudo cat {file_path}'
                pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
                content = pipe_cat_file.stdout
                if content:
                    content = content.split('\n')[:constants.END]
    return content


def get_field(information_fields, debug, container_name):
    """This function receives the requested field information."""
    os_release_path = '/etc/os-release'
    release_information = file_content(os_release_path, debug, container_name)
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


def check_distribution_with_alpine_support(debug, container_name):
    """This function checks if the machine is running on linux and if the os distribution is supported include alpine
    which has partial support."""
    if os_type.is_linux(debug, container_name):
        distribution = os_release.get_field(['Distribution'], debug, container_name)
        if distribution.lower() != ALPINE:
            if not os_type.is_supported_distribution(debug, container_name):
                return False
            return True
        print(constants.FULL_QUESTION_MESSAGE.format('Is the os distributions one of Ubuntu, Debian, Red, Centos, '
                                                     'Fedora, SUSE, SLES, Amazon, Alpine supported distributions?'))
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('The os distribution you are running on is Alpine which is one'
                                                        ' of the supported distributions'))
        return True
    return False


def is_supported_distribution(debug, container_name):
    """This function checks if the os distribution is supported."""
    information_fields = ['Distribution']
    host_information = get_field(information_fields, debug, container_name)
    if not host_information:
        return constants.UNSUPPORTED
    if host_information == constants.UNSUPPORTED or not host_information:
        return False
    if host_information in constants.APT_DISTRIBUTIONS or host_information in constants.RPM_DISTRIBUTIONS:
        return True
    return False


def is_linux(debug, container_name):
    """This function checks if the operation system is Linux."""
    os_type = 'uname -s'
    pipe_os_type = run_command.command_output(os_type, debug, container_name)
    os_type_output = pipe_os_type.stdout
    if 'Linux' in os_type_output:
        return True
    return False


def check_linux_supported_environment(debug, container_name, vulnerability_identifier):
    """This function checks if the machine is running on linux and if the os distribution is supported."""
    print(constants.FULL_QUESTION_MESSAGE.format('Is the environment supported by MI-X?'))
    if is_linux(debug, container_name):
        if vulnerability_identifier in constants.SUPPORTED_ALPINE_VULNERABILITIES:
            supported_distribution = check_distribution_with_alpine_support(debug, container_name)
        else:
            supported_distribution = is_supported_distribution(debug, container_name)
        if supported_distribution == constants.UNSUPPORTED or not supported_distribution:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('Your os distribution is unsupported'))
            return False
        else:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('Your environment is supported'))
            return True
    else:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your os is not Linux'))
    return False