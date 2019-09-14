#!/usr/bin/env python3
import os
from pathlib import Path


def get_arguments():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('--search', dest='search', required=False,
                        help='Optional. A query to search within the toolkit.')
    parser.add_argument('--download', dest='download', required=False,
                        help='Optional. Download a tool by it\'s name. The tool will be downloaded in a newly created '
                             'directory. Pass DOWNLOAD_ALL to download everything.')
    options = parser.parse_args()

    return options


options = get_arguments()

import logging

logging.basicConfig(format='[%(asctime)s %(levelname)s]: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level='INFO')


class Tool:
    def __init__(self, line):
        assert line and line.strip() != ''
        self.name = line.split('**')[1].split('**')[0]
        self.description = line.split('**')[2].split('http')[0].strip()
        self.url = 'http' + line.split('http')[1]
        self.category = None

    def is_tool_downloaded(self):
        path = os.getcwd() + '/' + self.category['alias'] + '/' + self.name
        return os.path.exists(path) and os.listdir(path)

    def find_category(self, readme_file):
        with open(readme_file, 'r') as file:
            sections = file.read().split('## ')
            for sec in sections:
                if self.url in sec:
                    category = sec.split('\n')[0]
                    self.category = {
                        'name': category,
                        'alias': category.lower().replace(' ', '-')
                    }

    def download(self):
        if self.is_tool_downloaded():
            logging.info('%s is already downloaded', self.name)
            return
        from git.repo.base import Repo

        logging.info('Downloading %s', self.name)
        path = Path(os.getcwd() + '/' + self.category['alias'] + '/' + self.name)
        path.mkdir(parents=True, exist_ok=True)
        try:
            Repo.clone_from(self.url, path)
        except Exception as e:
            logging.error('Downloading failed: %s', e)

    def printout(self):
        print(self.name + ' // ' + self.category['name'])
        print('DONWLOADED' if self.is_tool_downloaded() else 'NOT_DOWNLOADED')
        print(self.url)
        print(self.description)


def download_tool(tool_name, tools):
    for tool in tools:
        if tool.name == tool_name or tool_name == 'DOWNLOAD_ALL':
            tool.download()


def get_tools_from_readme(readme_file):
    tools = []
    with open(readme_file, 'r') as file:
        lines = [line.replace('\n', '') for line in file.readlines()]
        for line in lines:
            if line.startswith('* **'):
                tool = Tool(line)
                tool.find_category(readme_file)
                tools.append(tool)
    return tools


def get_scripts_from_readme(readme_file):
    scripts_url = []
    with open(readme_file, 'r') as file:
        file_content_as_string = [line.replace('\n', '') for line in file.readlines()]
        for line in file_content_as_string:
            if line.startswith('  * '):
                scripts_url.append(line.replace('  * ', ''))
    return scripts_url


def interact(tools):
    prefix = 'toolkit:>> '
    while True:
        command = input(prefix)
        if command == 'help' or command == '?':
            print('search <case insensitive query>')
            print('download <tool name>')
            print('download DOWNLOAD_ALL')
        if command.startswith('search '):
            query = command.split(' ')[1]
            search_in_tools(query, tools)
        if command.startswith('download '):
            tool_name = command.split(' ')[1]
            download_tool(tool_name, tools)


def search_in_tools(search, tools):
    logging.info('Searching for %s', search)
    matched_tools = []
    for tool in tools:
        if search.lower() in tool.name.lower() or search.lower() in tool.description.lower():
            matched_tools.append(tool)
    logging.info("%s tools found", len(matched_tools))
    for tool in matched_tools:
        tool.printout()
        print('*' * 60)


readme = 'README.md'

scripts = get_scripts_from_readme(readme)
tools = get_tools_from_readme(readme)
downloaded_tools = [t for t in tools if t.is_tool_downloaded()]

logging.info('## Red-Teaming-Toolkit initialized')
logging.info('%s tools initialized', len(tools))
logging.info('%s scripts initialized', len(scripts))
logging.info('%s tools downloaded', len(downloaded_tools))

try:
    if options.search:
        search_in_tools(options.search, tools)
    elif options.download:
        download_tool(options.download, tools)
    else:
        interact(tools)
except KeyboardInterrupt:
    logging.info('Keyboard interrupt, exiting')
    exit(0)
except Exception as e:
    logging.error('Unexpected error: %s', e)
