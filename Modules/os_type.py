"""
Support for modules which written for avoiding repetitive code.
"""
from Modules import run_command, constants

BASIC_COLOR = '\033[00m'
EXPLANATION = '\033[90m'
POSITIVE_RESULT = '\033[92m'
NEGATIVE_RESULT = '\033[91m'
QUESTION = '\033[94m'


def linux(debug, container_name):
    """This function checks if the operation system is Linux."""
    os_type = 'uname -s'
    print(constants.FULL_QUESTION_MESSAGE.format('Is it Linux?'))
    pipe_os_type = run_command.command_output(os_type, debug, container_name)
    os_type_output = pipe_os_type.stdout
    if 'Linux' in os_type_output:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('You are running on a Linux operation system'))
        return True
    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format('You are not running on a Linux operation system'))
    return False
