"""
Support for modules which written for avoiding repetitive code.
"""
from modules import constants


def vulnerable(vulnerability):
    """This function prints and return the status of vulnerable."""
    print(constants.FULL_VULNERABLE_MESSAGE.format(vulnerability))
    return constants.VULNERABLE


def not_vulnerable(vulnerability):
    """This function prints and return the status of not vulnerable."""
    print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(vulnerability))
    return constants.NOT_VULNERABLE


def not_determined(vulnerability):
    """This function prints and return the status of not determined."""
    print(constants.FULL_NOT_DETERMINED_MESSAGE.format(vulnerability))
    return constants.NOT_DETERMINED


def process_vulnerable(vulnerability, pid):
    """This function prints and return the status of not vulnerable process."""
    print(constants.FULL_PROCESS_VULNERABLE_MESSAGE.format(vulnerability, pid))
    return constants.VULNERABLE


def process_not_vulnerable(vulnerability, pid):
    """This function prints and return the status of vulnerable process."""
    print(constants.FULL_PROCESS_NOT_VULNERABLE_MESSAGE.format(vulnerability, pid))
    return constants.NOT_VULNERABLE


def process_not_determined(vulnerability, pid):
    """This function prints and return the status of not determined process."""
    print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(vulnerability, pid))
    return constants.NOT_DETERMINED


def remediation_mitigation(remediation, mitigation):
    """This function prints out the remediation of mitigation if exists."""
    if remediation:
        print(constants.FULL_REMEDIATION_MESSAGE.format(remediation))
    if mitigation:
        print(constants.FULL_MITIGATION_MESSAGE.format(mitigation))
