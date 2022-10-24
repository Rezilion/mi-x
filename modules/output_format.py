"""
Support for csv, json, os and other modules which written for avoiding repetitive code.
"""
import json
import csv
import os
from modules import constants

JSON ='json'
CSV = 'csv'
TEXT = 'text'
DICT_TYPE = 'dict'
STR_TYPE = 'str'
HOST ='host'


def open_file(format, container_name):
    """This function checks if the file exists, if not - it opens the file in write mode, if yes - opens the file in
    append mode."""
    if container_name:
        file_name = container_name
    else:
        file_name = HOST
    path = file_name + '.' + format
    if not os.isfile(path):
        file = open(path, 'w+')
    else:
        file = open(path, 'a')
    return file


def set_csv_line(vulnerability, state):
    """This function creates the lines that will be inserted into the csv file."""
    line = []
    if state == constants.VULNERABLE:
        line = [vulnerability, HOST, '', '']
    elif state == constants.NOT_VULNERABLE:
        line = [vulnerability, '', HOST, '']
    elif state == constants.NOT_DETERMINED:
        line = [vulnerability, '', '', HOST]
    return line


def csv_format(state, container_name):
    """This function writes the summary into a csv file."""
    header = ['vulnerability', 'vulnerable', 'not vulnerable', 'not determined']
    file = open_file(CSV, container_name)
    content = []
    for value in state:
        if DICT_TYPE in str(type(state[value])):
            for pid in state[value]:
                vulnerability = value + '-' + pid
                state_value = state[value][pid]
                content.append(set_csv_line(vulnerability, state_value))
        elif STR_TYPE in str(type(state[value])):
            content.append(set_csv_line(value, state[value]))
    writer = csv.writer(file)
    writer.writerow(header)
    for line in content:
        writer.writerow(line)
    file.close()


def text_format(state, container_name):
    """This function writes the summary into a text file."""
    file = open_file(TEXT, container_name)
    for value in state:
        if DICT_TYPE in str(type(state[value])):
            file.write(value)
            for pid in state[value]:
                state_value = state[value][pid]
                file.write(state[value] + ' : ' + state_value)
            file.write('\n')
        elif STR_TYPE in str(type(state[value])):
            file.write(value + ' : ' + state[value] + '\n')
    file.close()


def json_format(state, container_name):
    """This function writes the summary into a json file."""
    file = open_file(JSON, container_name)
    json_object = json.dumps(state)
    file.write(json_object)
    file.close()


def format_type(format, state, container_name):
    """This function checks the format type."""
    if format.lower() == JSON:
        json_format(state, container_name)
    elif format.lower() == TEXT:
        text_format(state, container_name)
    elif format.lower() == CSV:
        csv_format(state, container_name)
    else:
        print('Invalid format value')
        