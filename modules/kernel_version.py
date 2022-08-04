"""
Support for semver and other modules which written for avoiding repetitive code.
"""
from packaging import version
from modules import run_command, commons, constants

BASIC_COLOR = '\033[00m'
EXPLANATION = '\033[90m'
NEGATIVE_RESULT = '\033[91m'
POSITIVE_RESULT = '\033[92m'
QUESTION = '\033[94m'


def check_kernel(min_kernel_version, max_kernel_version, debug):
    """This function checks if the host kernel is affected according to the fixed kernel release."""
    affected = False
    kernel_version_command = 'uname -r'
    print(constants.FULL_QUESTION_MESSAGE.format('Is kernel version affected?'))
    pipe_kernel_version = run_command.command_output(kernel_version_command, debug, container_name=False)
    kernel_version = pipe_kernel_version.stdout
    valid_kernel_version = commons.valid_kernel_version(kernel_version)
    if not valid_kernel_version:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Kernel version unsupported value'))
        return constants.UNSUPPORTED
    if version.parse(max_kernel_version) > version.parse(valid_kernel_version) > version.parse(min_kernel_version):
        affected = True
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'According to your os release, affected kernel versions are '
                                                        f'between: {min_kernel_version} to {max_kernel_version}\nYour '
                                                        f'kernel version which is{valid_kernel_version[:constants.END]}'
                                                        f', is potentially affected'))
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'According to your os release, affected kernel versions are '
                                                        f'between: {min_kernel_version} to {max_kernel_version}\nYour '
                                                        f'kernel version which is{valid_kernel_version[:constants.END]}'
                                                        f', is not affected'))
    return affected


def get_kernel_version(debug):
    """This function returns the kernel version."""
    kernel_version_command = 'uname -r'
    pipe_kernel_version = run_command.command_output(kernel_version_command, debug, container_name=False)
    kernel_version = pipe_kernel_version.stdout
    if kernel_version:
        return kernel_version
    return False
