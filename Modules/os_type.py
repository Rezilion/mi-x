"""
Support for modules which written for avoiding repetitive code.
"""
from Modules import run_command, constants, os_release

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
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('You are running on a Linux operation system'))
        information_fields = ['Distribution']
        host_information = os_release.get_field(information_fields, debug, container_name)
        print(constants.FULL_QUESTION_MESSAGE.format('Is the os distributions one of Ubuntu, Debian, Red, Centos, '
                                                     'Fedora, SUSE, SLES, Amazon supported distributions?'))
        if host_information == constants.UNSUPPORTED or not host_information:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The os distribution you are running on is '
                                                            f'{host_information} which is not one of the supported '
                                                            f'distributions'))
            return False
        if host_information in constants.APT_DISTRIBUTIONS or host_information in constants.RPM_DISTRIBUTIONS:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The os distribution you are running on is '
                                                            f'{host_information} which is one of the supported '
                                                            f'distributions'))
            return True
    print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('You are not running on a supported operation system'))
    return False
