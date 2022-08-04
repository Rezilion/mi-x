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
        print(f'{EXPLANATION}Kernel version unsupported value{BASIC_COLOR}')
        return 'Unsupported'
    if version.parse(max_kernel_version) > version.parse(valid_kernel_version) > version.parse(min_kernel_version):
        affected = True
        print(f'{NEGATIVE_RESULT}Yes{BASIC_COLOR}')
    else:
        print(f'{POSITIVE_RESULT}No{BASIC_COLOR}')
    print(f'{EXPLANATION}According to your os release, affected kernel versions are between: {min_kernel_version}'
          f' to {max_kernel_version}')
    print(f'Your kernel version: {valid_kernel_version[:constants.END]}{BASIC_COLOR}')
    return affected


def get_kernel_version(debug):
    """This function returns the kernel version."""
    kernel_version_command = 'uname -r'
    pipe_kernel_version = run_command.command_output(kernel_version_command, debug, container_name=False)
    kernel_version = pipe_kernel_version.stdout
    if kernel_version:
        return kernel_version
    return False
