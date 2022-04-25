import Modules.constants as constants
import Modules.run_command as run_command
import semver

BASIC_COLOR = '\033[00m'
EXPLANATION = '\033[90m'
NEGATIVE_RESULT = '\033[91m'
POSITIVE_RESULT = '\033[92m'
QUESTION = '\033[94m'


# This function checks if the host kernel is vulnerable according to the fixed kernel release.
def check_kernel(min_kernel_version, max_kernel_version, debug, container_name):
    vulnerable = False
    kernel_version_command = 'uname -r'
    print(constants.FULL_QUESTION_MESSAGE.format('Is kernel version affected?'))
    pipe_kernel_version = run_command.command_output(kernel_version_command, debug, container_name)
    kernel_version = pipe_kernel_version.stdout
    if kernel_version:
        if semver.compare(max_kernel_version, kernel_version) == 1 and \
                semver.compare(min_kernel_version, kernel_version) == -1:
            vulnerable = True
            print(f'{NEGATIVE_RESULT}Yes{BASIC_COLOR}')
        else:
            print(f'{POSITIVE_RESULT}No{BASIC_COLOR}')
        print(f'{EXPLANATION}According to your os release, vulnerable kernel versions are between: {min_kernel_version}'
              f' to {max_kernel_version}')
        print(f'Your kernel version: {kernel_version[:constants.END]}{BASIC_COLOR}')
    else:
        print(f'{EXPLANATION}Kernel version unsupported value{BASIC_COLOR}')
        return 'Unsupported'
    return vulnerable


# This function returns the kernel version.
def get_kernel_version(debug, container_name):
    kernel_version_command = 'uname -r'
    if container_name:
        kernel_version_command = constants.DOCKER_EXEC_COMMAND.format(container_name, kernel_version_command)
    pipe_kernel_version = run_command.command_output(kernel_version_command, debug, container_name)
    kernel_version = pipe_kernel_version.stdout
    if kernel_version:
        return kernel_version
    else:
        return False