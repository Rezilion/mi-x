"""
Support for re, version from packaging and other modules written to avoid repetitive code.
"""
import re
from packaging import version
from modules import constants


def re_start_of_version(full_version):
    """Returns the start of a version using regex."""
    start_of_version = re.search(r'\d*\.\d*', full_version)
    if start_of_version:
        return start_of_version.group()


def check_patched_version(version_type, checked_version, patched_versions):
    """This function checks if the version is affected according to patched versions which sorted in an ascending order
     list."""
    affected = False
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is {version_type} version affected?'))
    if patched_versions[0] in checked_version:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {version_type} version which is: {checked_version} has '
                                                        f'the patched version which is: '
                                                        f'{patched_versions[0]}'))
    elif version.parse(checked_version) < version.parse(patched_versions[0]):
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The lowest patched version is: '
                                                        f'{patched_versions[0]}\nYour {version_type}'
                                                        f' version which is: {checked_version}, is affected'))
        affected = True
    elif version.parse(checked_version) > version.parse(patched_versions[-1]) or \
            patched_versions[-1] in checked_version:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The highest patched version is: '
                                                        f'{patched_versions[-1]}\nYour {version_type}'
                                                        f' version is: {checked_version}'))
    else:
        for patched_version in patched_versions[1 :]:
            start_of_checked_version = re_start_of_version(checked_version)
            start_of_patched_version = re_start_of_version(patched_version)
            if version.parse(start_of_checked_version) < version.parse(start_of_patched_version):
                print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {version_type} version which is: '
                                                                f'{checked_version} is not patched'))
                affected = True
                break
            if patched_version.startswith(start_of_checked_version):
                if version.parse(checked_version) < version.parse(patched_version):
                    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The lowest patched version is: {patched_version}'
                                                                    f'\nYour {version_type} version is: '
                                                                    f'{checked_version}, is affected'))
                    affected = True
                    break
                if patched_version in checked_version:
                    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {version_type} version which is: '
                                                                    f'{checked_version} has the patched version which '
                                                                    f'is: {patched_versions}, is not affected'))
                else:
                    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The lowest patched version is: {patched_version}'
                                                                    f'\nYour {version_type} version which is: '
                                                                    f'{checked_version}, is not affected'))
                    break
    return affected


def compare_versions(fixed_version, host_version, package_name):
    """This function compares between the fixed version and the host's version."""
    affected = False
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is {package_name} version affected?'))
    if version.parse(fixed_version) < version.parse(host_version):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {package_name} patched versions is: {fixed_version}\nYour'
                                                        f' versions which is: {host_version}, is not affected'))
    elif version.parse(fixed_version) == version.parse(host_version):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your system is not affected because it has the {package_name}'
                                                        f' patched version which is: {fixed_version}'))
    else:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {package_name} patched versions is: {fixed_version}\nYour'
                                                        f' versions which is: {host_version}, is affected'))
        affected = True
    return affected
