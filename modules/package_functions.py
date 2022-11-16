"""
Support for modules written to avoid repetitive code.
"""
from modules import constants, run_command

PACKAGE_VERSION_FIELD = 'Version'
PACKAGE_RELEASE_FIELD = 'Release'
PACKAGE_INSTALLED_FIELD = 'Installed'
ERROR_MESSAGE = 'Unable to locate package'
NONE = 'none'


def get_package(distribution, package_name, debug, container_name):
    """This function get distribution and package name and returns the package information if exists."""
    if distribution in constants.APT_DISTRIBUTIONS:
        package_info_command = f'apt-cache policy {package_name}'
    elif distribution in constants.RPM_DISTRIBUTIONS:
        package_info_command = f'rpm -qi {package_name}'
    else:
        return ''
    package_output = run_command.command_output(package_info_command, debug, container_name).stdout
    if package_output.endswith('is not installed\n'):
        return ''
    return package_output


def package_version_rpm(distribution, package_name, debug, container_name):
    """This function returns the policy version and release for distributions with rpm package manager."""
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is there an affected {package_name} package installed?'))
    package_info = get_package(distribution, package_name, debug, container_name)
    if not package_info:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'{package_name} is not installed on the host'))
        return []
    check = False
    host_info = []
    for field in package_info.split('\n'):
        if PACKAGE_VERSION_FIELD in field:
            host_version = field.split(': ')[constants.END]
            if host_version.endswith('\n'):
                host_info.append(host_version[:constants.END])
                check = True
        if check:
            if PACKAGE_RELEASE_FIELD in field:
                host_info.append(field.split(': ')[constants.FIRST])
                print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'{package_name} is installed on the host'))
                return host_info
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'{package_name} is not installed on the host'))
    return host_info


def package_version_apt(distribution, package_name, debug, container_name):
    """This function returns the policy installed version for distributions with apt package manager."""
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is there an affected {package_name} package installed?'))
    policy_info = get_package(distribution, package_name, debug, container_name)
    if not policy_info:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'{package_name} is not installed on the host'))
        return ''
    package_version = ''
    for field in policy_info.split('\n'):
        if PACKAGE_INSTALLED_FIELD in field:
            package_version = field.split(': ')[constants.FIRST]
            break
    if not package_version or ERROR_MESSAGE in package_version or NONE in package_version:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'{package_name} is not installed on the host'))
        return ''
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'{package_name} is installed on the host'))
    return package_version
