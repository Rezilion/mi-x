import Modules.constants as constants
import Modules.run_command as run_command


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
