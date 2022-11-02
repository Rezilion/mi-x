"""
Support for semver and other modules which written for avoiding repetitive code.
"""
import re
from packaging import version
from modules import run_command, constants


def get_kernel_version(debug):
    """This function returns the kernel version."""
    kernel_version_command = 'uname -r'
    pipe_kernel_version = run_command.command_output(kernel_version_command, debug, container_name='')
    kernel_version = pipe_kernel_version.stdout
    if kernel_version:
        if kernel_version.endswith('\n'):
            kernel_version = kernel_version[:constants.END]
        return kernel_version
    return ''


def get_valid_kernel_version(debug):
    """Returns the start of a valid kernel version using regex."""
    full_version = get_kernel_version(debug)
    if not full_version:
        return ''
    if full_version.endswith('\n'):
        full_version = full_version[:constants.END]
    kernel_version = ''
    kernel_version_regex = re.search(r'\d*\.\d*.\d*-\d*.\d*', full_version) 
    if kernel_version_regex:
        kernel_version = kernel_version_regex.group()
        if kernel_version.endswith('-'):
            kernel_version = kernel_version[:constants.END]
    return kernel_version


def check_kernel(min_kernel_version, max_kernel_version, debug):
    """This function checks if the host kernel is affected according to the fixed kernel release."""
    print(constants.FULL_QUESTION_MESSAGE.format('Is kernel version affected?'))
    valid_kernel_version = get_valid_kernel_version(debug)
    if not valid_kernel_version:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Kernel version unsupported value'))
        return constants.UNSUPPORTED
    affected = ''
    if version.parse(max_kernel_version) > version.parse(valid_kernel_version) > version.parse(min_kernel_version):
        affected = 'True'
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'According to your os release, affected kernel versions are '
                                                        f'between: {min_kernel_version} to {max_kernel_version}\nYour '
                                                        f'kernel version which is: '
                                                        f'{valid_kernel_version[:constants.END]}, is potentially '
                                                        f'affected'))
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'According to your os release, affected kernel versions are '
                                                        f'between: {min_kernel_version} to {max_kernel_version}\nYour '
                                                        f'kernel version which is: '
                                                        f'{valid_kernel_version[:constants.END]}, is not affected'))
    return affected
