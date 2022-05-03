import Modules.constants as constants
import Modules.run_command as run_command

PACKAGE_VERSION_FIELD = 'Version'
PACKAGE_RELEASE_FIELD = 'Release'
PACKAGE_INSTALLED_FIELD = 'Installed'
NONE = 'none'


# This function get distribution and package name and returns the package information if exists.
def package(distribution, package_name, debug, container_name):
    if distribution in constants.APT_DISTRIBUTIONS:
        package_info_command = f'apt-cache policy {package_name}'
    elif distribution in constants.RPM_DISTRIBUTIONS:
        package_info_command = f'rpm -qi {package_name}'
    else:
        return ''
    package_output = run_command.command_output(package_info_command, debug, container_name).stdout
    if package_output.endswith('is not installed\n'):
        return ''
    return run_command.command_output(package_info_command, debug, container_name).stdout


# This function returns the policy version and release for distributions with rpm package manager.
def package_version_rpm(distribution, package_name, debug, container_name):
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is there an affected {package_name} package installed?'))
    package_info = package(distribution, package_name, debug, container_name)
    if package_info:
        check = False
        host_info = []
        for field in package_info.split('\n'):
            if field.__contains__(PACKAGE_VERSION_FIELD):
                host_version = field.split(': ')[constants.END]
                if host_version.endswith('\n'):
                    host_info.append(host_version[:constants.END])
                    check = True
            if check:
                if field.__contains__(PACKAGE_RELEASE_FIELD):
                    host_info.append(field.split(': ')[constants.FIRST])
                    return host_info
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'{package_name} is not installed on the host'))
        return []


# This function returns the policy installed version for distributions with apt package manager.
def package_version_apt(distribution, package_name, debug, container_name):
    print(constants.FULL_QUESTION_MESSAGE.format('Is there an affected Policy Kit package installed?'))
    policy_info = package(distribution, package_name, debug, container_name)
    if policy_info:
        package_version = ''
        for field in policy_info.split('\n'):
            if field.__contains__(PACKAGE_INSTALLED_FIELD):
                package_version = field.split(': ')[constants.FIRST]
                break
        if not package_version or package_version.__contains__(NONE):
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'{package_name} is not installed on the host'))
            return ''
        else:
            return package_version
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'{package_name} is not installed on the host'))
        return ''