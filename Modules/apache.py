"""
Support for modules which written for avoiding repetitive code.
"""
from Modules import run_command, os_release, constants

APACHE = 'apache2'
HTTPD = 'httpd'


def distribution_to_apache(debug, container_name):
    """This function checks the host distribution and returns the apache command in accordance."""
    information_fields = ['Distribution']
    host_information = os_release.get_field(information_fields, debug, container_name)
    print(constants.FULL_QUESTION_MESSAGE.format('Is os distribution affected?'))
    if host_information == constants.UNSUPPORTED:
        return host_information
    if not host_information:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine distribution, unsupported distribution '
                                                        'value'))
        return constants.UNSUPPORTED
    return_value = ''
    if host_information in constants.APT_DISTRIBUTIONS:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected os distributions: {constants.APT_DISTRIBUTIONS} '
                                                        f'{constants.RPM_DISTRIBUTIONS}\nYour os distribution: '
                                                        f'{host_information}\nThe os distribution you are running '
                                                        f'on is potentially affected'))
        return_value = APACHE
    elif host_information in constants.RPM_DISTRIBUTIONS:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected os distributions: {constants.APT_DISTRIBUTIONS} '
                                                        f'{constants.RPM_DISTRIBUTIONS}\nYour os distribution: '
                                                        f'{host_information}\nThe os distribution you are running '
                                                        f'on is potentially affected'))
        return_value = HTTPD
    elif host_information not in constants.APT_DISTRIBUTIONS and \
            host_information not in constants.RPM_DISTRIBUTIONS:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Can not determine'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected os distributions: {constants.APT_DISTRIBUTIONS} '
                                                        f'{constants.RPM_DISTRIBUTIONS}\nYour os distribution: '
                                                        f'{host_information}\nThe os distribution you are running '
                                                        f'on is not supported'))
        return_value = constants.UNSUPPORTED
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected os distributions: {constants.APT_DISTRIBUTIONS} '
                                                        f'{constants.RPM_DISTRIBUTIONS}\nYour os distribution: '
                                                        f'{host_information}\nThe os distribution you are running '
                                                        f'on is not affected'))
    return return_value


def loaded_modules(apache, module_name, debug, container_name):
    """This function checks if the cgi_module is loaded."""
    loaded_modules_command = f'{apache} -M'
    pipe_modules = run_command.command_output(loaded_modules_command, debug, container_name)
    modules = pipe_modules.stdout
    if not 'Loaded Modules:' in modules:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine loaded modules, unsupported value'))
        return constants.UNSUPPORTED
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is "{module_name}" module loaded?'))
    if module_name in modules:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "{module_name}" module is loaded'))
        return True
    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "{module_name}" module is not loaded'))
    return False
