"""Async and await example using subprocesses

https://fredrikaverpil.github.io/2017/06/20/async-and-await-with-subprocesses/

Note:
    Requires Python 3.6.
"""

import sys
import time
import platform
import asyncio
from pprint import pprint


async def run_command(*args):
    """Run command in subprocess.

    Example from:
        http://asyncio.readthedocs.io/en/latest/subprocess.html
    """
    process = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    print(f"Started: {args}, pid={process.pid}", flush=True)

    stdout, stderr = await process.communicate()
    if process.returncode == 0:
        print(f"Done: {args}, pid={process.pid}, result: {stdout.decode('cp1251').strip()}", flush=True)
    else:
        print(f"Failed: {args}, pid={process.pid}, result: {stderr.decode('cp1251').strip()}", flush=True)
    result = stdout.decode().strip()

    return result


def make_chunks(l, n):
    """Yield successive n-sized chunks from l.

    Note:
        Taken from https://stackoverflow.com/a/312464
    """
    for i in range(0, len(l), n):
        yield l[i : i + n]


def run_asyncio_commands(tasks, max_concurrent_tasks=0):
    """Run tasks asynchronously using asyncio and return results.

    If max_concurrent_tasks are set to 0, no limit is applied.

    Note:
        By default, Windows uses SelectorEventLoop, which does not support
        subprocesses. Therefore ProactorEventLoop is used on Windows.
        https://docs.python.org/3/library/asyncio-eventloops.html#windows
    """
    all_results = []

    if max_concurrent_tasks == 0:
        chunks = [tasks]
        num_chunks = len(chunks)
    else:
        chunks = make_chunks(l=tasks, n=max_concurrent_tasks)
        num_chunks = len(list(make_chunks(l=tasks, n=max_concurrent_tasks)))

    if asyncio.get_event_loop().is_closed():
        asyncio.set_event_loop(asyncio.new_event_loop())
    if platform.system() == "Windows":
        asyncio.set_event_loop(asyncio.ProactorEventLoop())
    loop = asyncio.get_event_loop()

    for i, tasks_in_chunk in enumerate(chunks):
        chunk = i + 1
        print(f"Beginning work on chunk {chunk}/{num_chunks}", flush=True)
        commands = asyncio.gather(*tasks_in_chunk)
        # TODO queueing instead of chunking?
        results = loop.run_until_complete(commands)
        all_results += results
        print(f"Completed work on chunk {chunk}/{num_chunks}", flush=True)

    loop.close()
    return all_results


def download_tools(urls: list):
    """Main program."""
    start = time.time()
    commands = [['git', 'clone', url] for url in urls]

    tasks = []
    for command in commands:
        tasks.append(run_command(*command))

    # # List comprehension example
    # tasks = [
    #     run_command(*command, get_project_path(project))
    #     for project in accessible_projects(all_projects)
    # ]

    results = run_asyncio_commands(tasks, max_concurrent_tasks=20)  # At most 20 parallel tasks
    print("Results:")
    pprint(results)

    end = time.time()
    rounded_end = "{0:.4f}".format(round(end - start, 4))
    print(f"Script ran in about {rounded_end} seconds", flush=True)


if __name__ == "__main__":
    REMOTE_URLS = [
        "https://github.com/derstolz/Red-Teaming-Toolkit",
        "https://github.com/mtalimanchuk/cli-win-utils",
        "https://github.com/derstolz/saltstack-monitor",
        "https://github.com/mtalimanchuk/flask-filebox",
        "https://github.com/mtalimanchuk/e-xercise",

    ]
    download_tools(REMOTE_URLS)
