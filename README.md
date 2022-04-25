# **'Am I Really Vulnerable?' - Readme**

 Author:                   2022-Now, Rezilion

 Description:              Vulnerabilities validation

 Development:              January 2022 - Now

 Documentation:            See website, README


# Introduction

## Description
‘Am I Really Vulnerable?’ is a python open source project that comes to meet the need of validating if your system is vulnerable to specific vulnerabilities.
The project can help you understand whether you are vulnerable to a specific vulnerability and explain to you what is the vulnerable component or invulnerable component in your system.
The project can create a graph that presents the validation flow according to the vulnerability checks we perform.
We want to create a community of researchers and programmers that can add vulnerability checks for new vulnerabilities or critical or famous vulnerabilities. Whenever a new vulnerability comes up, we can offer this service that helps people validate if they are vulnerable or not.
In addition, the vulnerabilities checks we wrote so far, can be expanded with some checks we might have missed.

## Features and usage options:
* Validate if vulnerable to provided cve
* Validate if vulnerable to category of cves
* Get the vulnerability description
* Validate the host containers
* Present the validation flow logic as a graph

Everyone is free to use 'Am I Really Vulnerable?' under the conditions of the Apache 2.0 License (see LICENSE file).
 
## Quick facts
   - **Name**:      'Am I Really Vulnerable?'
   - **Type**:      vulnerability validation
   - **License**:   GNU AFFERO GENERAL PUBLIC LICENSE
   - **Language**:  Python3
   - **Author**:    Ofri Ouzan, Rezilion
   - **Required Permissions**: root preferred, not needed (may use sudo)
   
# Files

- `am_i_really_vulnerable.py` - The main file which handles the user input and the CVEs calls.
- `CVEs` - Python package that contains a python file for each currently supported CVE.
- `Modules` - Python package that contains modules.
Modules are code implementations which are used in different CVE files.


# Color Legend

BASIC_COLOR 

EXPLANATION

NEGATIVE_RESULT

POSITIVE_RESULT

NEUTRAL_RESULT

QUESTION

VULNERABLE

NOT_VULNERABLE

# Installation Requirements

1. Python version 3
2. Graphviz (optional, needed only for the graph capabilities)


# Installation

The very latest developments can be obtained via git.

Clone or download the project files (no compilation nor installation is required) 

`git clone https://github.com/rezilion/amireallyvulnerable`

Execute:

`cd amireallyvulnerable && python3 am_i_really_vulnerable.py`

# Arguments

## --cve_id

Specifies the CVE ID that will be checked. 

Syntax: 
- all - runs all the vulnerabilities in the CVEs directory
- cve_year_id - runs specific cve by the vulnerability cve id
- name - runs specific cve by the vulnerability name

If the argument is not set, a menu message will appear presenting the currently supported vulnerabilities.


## --container

The user needs to specify whether to examine running containers on the host (False by default).
- When running with containers, the user will need to insert the user’s password for sudo use.

## --describe

The user needs to specify whether to see the CVE description or not (True by default).

## --graph

The user needs to specify whether to see the validation flow chart (False by default).

## --help

Help to understand how to run the code

# Execution Example

Execute the program using parameters

`python3 am_i_really_vulnerable.py -cve_id cve_yyyy_xxxx -container True -graph True`

# Supported Systems

'Am I Really Vulnerable?' currently supports Linux.

This tool is tested or confirmed to work with Linux systems.

# Development and Bugs

Found an issue, or have a great idea? Let us know:

* GitHub - https://github.com/rezilion/amireallyvulnerable
* E-mail - ofrio@rezilion.com

Contributions are appreciated and can be done via GitHub. 

See CONTRIBUTING.md for more information about how to submit them.

# Support

'Am I Really Vulnerable?' is tested on most common Linux operating systems. The documentation (README) and the debugging 
information (set the debug parameter to 'True'), should cover most questions and problems. 

Bugs can be reported via GitHub, or sending an e-mail to the email address above.

# Thanks

Thanks to the community for using and supporting open source software.

Many comments, bugs/patches and questions are the key to success and ongoing motivation in developing tools like this.
