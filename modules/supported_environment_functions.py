"""
Support for modules written to avoid repetitive code.
"""
from modules import constants, run_command, file_functions

NAME_FIELD = 'NAME='
VERSION_FIELD = 'VERSION_ID='


def file_content_host(file_path, debug, container_name):
    """This function returns the file's content if exists (in hosts)."""
    content = []
    if file_functions.check_file_existence(file_path, debug, container_name):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = []
                for line in file.readlines():
                    content.append(line[: -1])
        except PermissionError:
            cat_file_command = f'sudo cat {file_path}'
            pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
            content = pipe_cat_file.stdout
            if content:
                content = content.split('\n')[: -1]
    return content


def file_content_container(file_path, debug, container_name):
    """This function returns the file's content if exists (in containers)."""
    cat_file_command = f'cat {file_path}'
    pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
    content = pipe_cat_file.stdout
    if content:
        content = content.split('\n')[: -1]
    return content


def file_content(file_path, debug, container_name):
    """This function checks returns the file's content if exists."""
    if container_name:
        content = file_content_container(file_path, debug, container_name)
    else:
        content = file_content_host(file_path, debug, container_name)
    return content


def get_field(information_fields, debug, container_name):
    """This function receives the requested field information."""
    os_release_path = '/etc/os-release'
    release_information = file_content(os_release_path, debug, container_name)
    host_information = ''
    if release_information:
        for field in release_information:
            if 'Distribution' in information_fields and field.startswith(NAME_FIELD):
                distribution = field.split('=')[-1][1 : -1]
                distribution = distribution.split(' ')[0]
                if distribution == 'Debian' and field.endswith('sid"'):
                    return 'Debian unstable'
                host_information += distribution
            elif 'Version' in information_fields and field.startswith(VERSION_FIELD):
                if host_information:
                    host_information += ' '
                host_version = field.split('=')[1]
                if host_version.endswith('\n'):
                    host_version = host_version[: -1]
                if host_version.startswith('"') and host_version.endswith('"'):
                    host_version = host_version[1 : -1]
                host_information += host_version
    return host_information


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


def check_distribution_with_alpine_support(debug, container_name):
    """This function checks if the machine is running on linux and if the os distribution is supported include alpine
    which has partial support."""
    distribution = get_field(['Distribution'], debug, container_name)
    if distribution.lower() != constants.ALPINE:
        if not is_supported_distribution(debug, container_name):
            return False
        return True
    return True


def get_os(debug, container_name):
    """This function checks if the operating system is Linux."""
    check_os_command = 'uname -s'
    running_os_type = ''
    try:
        pipe_os_type = run_command.command_output(check_os_command, debug, container_name)
        os_type_output = pipe_os_type.stdout
        if constants.LINUX in os_type_output.lower():
            running_os_type = constants.LINUX
    except FileNotFoundError:
        check_os_command = 'cmd.exe /c ver'
        try:
            pipe_os_type = run_command.command_output(check_os_command, debug, container_name)
            os_type_output = pipe_os_type.stdout
            if constants.WINDOWS in os_type_output.lower():
                running_os_type = constants.WINDOWS
        except FileNotFoundError:
            running_os_type = ''
    return running_os_type


def check_supported_environment(vulnerability_identifier, debug, container_name):
    """This function checks if the machine is running on linux and if the os distribution is supported."""
    print(constants.FULL_QUESTION_MESSAGE.format('\n\nIs the environment supported by MI-X?'))
    running_os_type = get_os(debug, container_name)
    if running_os_type == constants.LINUX:
        if vulnerability_identifier in constants.SUPPORTED_ALPINE_VULNERABILITIES:
            supported_distribution = check_distribution_with_alpine_support(debug, container_name)
        else:
            supported_distribution = is_supported_distribution(debug, container_name)
        if supported_distribution == constants.UNSUPPORTED or not supported_distribution:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('Your OS distribution is unsupported'))
            return ''
        else:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('Your environment is supported'))
    elif running_os_type == constants.WINDOWS:
        if vulnerability_identifier in constants.WINDOWS_VULNERABILITIES:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('Your environment is supported'))
        else:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('Your OS distribution is unsupported'))
            return ''
    else:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your OS distribution is unsupported'))
        return ''
    return running_os_type
