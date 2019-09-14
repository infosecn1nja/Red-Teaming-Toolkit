#!/usr/bin/env python3
import logging
import os
from argparse import ArgumentParser
from pathlib import Path

from git.repo.base import Repo


def get_arguments():
    parser = ArgumentParser()
    parser.add_argument('--search', dest='search', required=False,
                        help='Optional. A query to search within the toolkit.')
    parser.add_argument('--download', dest='download', required=False,
                        help='Optional. Download a tool by it\'s name. The tool will be downloaded in a newly created '
                             'directory. Pass DOWNLOAD_ALL to download everything.')
    parser.add_argument('--show', dest='show', required=False,
                        help='Optional. Show details about the given tool. If a tool has a readme file then it will '
                             'be printed to stdout.')
    parser.add_argument('--logging', dest='logging', choices=['INFO', 'DEBUG', 'WARNING', 'ERROR'], default='INFO',
                        help='Optional. Logging level.')
    options = parser.parse_args()

    return options


options = get_arguments()

logging.basicConfig(format='[%(asctime)s %(levelname)s]: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=options.logging)

git_sources = [
    'github.com',
    'bitbucket.com'
]


class Tool:
    @staticmethod
    def find_category(url, readme_file):
        with open(readme_file, 'r', encoding='utf-8') as file:
            sections = file.read().split('## ')
            for sec in sections:
                if url in sec:
                    category = sec.split('\n')[0]
                    return {
                        'name': category,
                        'alias': category.lower().replace(' ', '-')
                    }

    @staticmethod
    def fetch_tool_readme(tool_path, tool_name):
        readme_path = str(tool_path) + '/README.md'
        if os.path.exists(readme_path):
            logging.debug('README.md file has been extracted for %s', tool_name)
            return open(readme_path, 'r', encoding='utf-8').read()

    def __init__(self, line, file_content_as_string):
        assert line and line.strip() != ''
        self.name = line.split('**')[1].split('**')[0]
        self.description = line.split('**')[2].split('http')[0].strip()
        self.url = 'http' + line.split('http')[1]
        self.category = self.find_category(self.url, file_content_as_string)
        self.path = Path(os.getcwd() + '/' + self.category['alias'] + '/' + self.name)
        self.tool_readme = self.fetch_tool_readme(str(self.path), self.name) if self.is_downloaded() else None

    def is_downloaded(self):
        return os.path.exists(self.path) and os.listdir(self.path)

    def download(self):
        if self.is_downloaded():
            logging.info('%s is already downloaded', self.name)
            return
        if not any(host in self.url for host in git_sources):
            logging.warning('Skipping %s / %s downloading, as it doesn\'t look like a git repository', self.name,
                            self.url)
            return

        logging.info('Downloading %s', self.name)
        self.path.mkdir(parents=True, exist_ok=True)
        try:
            Repo.clone_from(self.url, self.path)
        except Exception as e:
            logging.error('Downloading failed: %s', e)
            os.rmdir(self.path)

    def printout(self, verbose=False):
        print(self.name + ' // ' + self.category['name'])
        print('DOWNLOADED' if self.is_downloaded() else 'NOT_DOWNLOADED')
        print(self.url)
        print(self.description)
        if verbose:
            if self.tool_readme:
                print(self.tool_readme)


def download_tool(tool_name, tools):
    for tool in tools:
        if tool.name == tool_name or tool_name == 'DOWNLOAD_ALL':
            tool.download()


def get_tools_from_readme(readme_file):
    tools = []
    with open(readme_file, 'r', encoding='utf-8') as file:
        lines = [line.replace('\n', '') for line in file.readlines()]
        for line in lines:
            if line.startswith('* **'):
                tool = Tool(line, readme_file)
                tools.append(tool)
    return tools


def show_tool_info(tool_name, tools):
    tool_found = False
    for tool in tools:
        if tool_name == tool.name:
            tool_found = True
            tool.printout(True)
    if not tool_found:
        logging.error('Tool %s wasn\'t found', tool_name)


def get_scripts_from_readme(readme_file):
    scripts_url = []
    with open(readme_file, 'r', encoding='utf-8') as file:
        file_content_as_string = [line.replace('\n', '') for line in file.readlines()]
        for line in file_content_as_string:
            if line.startswith('  * '):
                scripts_url.append(line.replace('  * ', ''))
    return scripts_url


def interact(tools):
    prefix = 'red-teaming-toolkit:>> '

    def search(command, tools):
        query = command.split(' ')[1]
        search_in_tools(query, tools)

    def download(command, tools):
        tool_name = command.split(' ')[1]
        download_tool(tool_name, tools)

    def show(command, tools):
        tool_name = command.split(' ')[1]
        show_tool_info(tool_name, tools)

    def help():
        print('search <case insensitive query>')
        print('download <tool name>')
        print('download DOWNLOAD_ALL')
        print('show <tool name>')

    while True:
        command = input(prefix)
        if command == 'help' or command == '?':
            help()
        if command.startswith('search '):
            search(command, tools)
        if command.startswith('download '):
            download(command, tools)
        if command.startswith('show '):
            show(command, tools)


def search_in_tools(search, tools):
    logging.info('Searching for %s', search)
    matched_tools = []
    for tool in tools:
        pattern = search.lower()
        if pattern in tool.name.lower() \
                    or pattern in tool.description.lower() \
                    or (pattern in tool.tool_readme.lower() if tool.tool_readme else False):
            matched_tools.append(tool)
    logging.info("%s tools found", len(matched_tools))
    for tool in matched_tools:
        tool.printout()
        print('*' * 60)


readme = 'README.md'

scripts = get_scripts_from_readme(readme)
tools = get_tools_from_readme(readme)
downloaded_tools = [t for t in tools if t.is_downloaded()]
categories = set([t.category['alias'] for t in tools])

logging.info('## Red-Teaming-Toolkit initialized')
logging.info('%s categories discovered', len(categories))
logging.info('%s tools synchronized', len(tools))
logging.info('%s tools downloaded', len(downloaded_tools))
logging.info('%s scripts synchronized', len(scripts))

try:
    if options.search:
        search_in_tools(options.search, tools)
    elif options.download:
        download_tool(options.download, tools)
    elif options.show:
        show_tool_info(options.show, tools)
    else:
        interact(tools)
except KeyboardInterrupt:
    logging.info('Keyboard interrupt, exiting')
    exit(0)
except Exception as e:
    logging.error('Unexpected error: %s', e)
