# Copyright (c) 2015 Codenomicon Ltd.
# License: MIT

from __future__ import absolute_import, division, print_function

import json
import os.path
from tempfile import NamedTemporaryFile
from zipfile import ZipFile
import click
import time
import functools
import sys

from protecodesc.protecodesc import ProtecodeSC
from protecodesc.config import AppcheckClientConfig
from protecodesc.utils import clean_version, zip_directory
from protecodesc import exceptions

import logging

logger = logging.getLogger(__name__)

VERDICT_PASS_SYMBOL = u"\U0001F60A"  # SMILING FACE WITH SMILING EYES
VERDICT_FAIL_SYMBOL = u"\U0001F622"  # CRYING FACE
VERDICT_VERIFY_SYMBOL = u"\U0001f440"  # EYES

# Default to Codenomicon online service
DEFAULT_APPCHECK_HOST = 'https://protecode-sc.com'


def get_appcheck(insecure=False):
    config = AppcheckClientConfig()
    username, password = config.credentials()
    if not (username and password):
        click.echo("Login required.")
        username, password = update_login_credentials()
    # Support alternate Appcheck address, e.g. appliance.
    appcheck_host = config.get_appcheck_host() or DEFAULT_APPCHECK_HOST
    appcheck = ProtecodeSC(creds=(username, password), host=appcheck_host,
                        insecure=insecure)
    return appcheck


def use_appcheck(f):
    """Decorator that initializes Appcheck instance"""

    @click.option('--insecure/--verify-ssl', help="Do not verify TLS certificate for HTTPS")
    @functools.wraps(f)
    def inner(insecure, **kwargs):
        if insecure:
            # If user chose to use insecure explicitly, ignore warnings...
            try:
                import requests.packages.urllib3 as urllib3
                urllib3.disable_warnings()
                click.echo("Warning: Not verifying TLS certificates.")
            except ImportError:
                pass  # If requests moves urllib3 around
        appcheck = get_appcheck(insecure=insecure)
        f(appcheck, **kwargs)
    return inner


@click.group(help="Protecode SC commandline tools. To use this tool you need "
                  "to have an account on the service.")
def cli():
    """Protecode SC command line utility"""


@cli.add_command
@click.command()
@use_appcheck
def groups(appcheck):
    """List groups"""
    res = appcheck.list_groups()
    click.echo('Available groups')
    click.echo('{id:8s} {name}'.format(id='ID', name='Name'))
    for g in res['groups']:
        click.echo('{id:<8d} {name}'.format(**g))


@cli.add_command
@click.option('--group', help="Show applications in GROUP", metavar="GROUP")
@click.command()
@use_appcheck
def list(appcheck, group):
    """List apps"""
    apps = appcheck.list_apps(group=group)

    app_format = u"{id:5s}  {name}"
    if len(apps['products']) > 0:
        click.echo(app_format.format(id="ID", name="Application name"))
        for p in apps['products']:
            click.echo(app_format.format(id=str(p['id']),
                                         name=p['name']))
    else:
        click.echo("No apps found.")


@cli.add_command
@click.argument('id_or_sha1', 'Analysis ID or file SHA1 hash')
@click.option('json_output', '--json/--human', default=False,
              help='Output in machine-readable JSON or human')
@click.command()
@use_appcheck
def result(appcheck, id_or_sha1, json_output):
    """Get scan result"""
    _print_result(appcheck, id_or_sha1=id_or_sha1, json_output=json_output)


@cli.add_command
@click.argument('id_or_sha1', 'Analysis ID or file SHA1 hash')
@click.option('--background/--wait', help="Scan in background; default: wait for results", default=False)
@click.command()
@use_appcheck
def rescan(appcheck, id_or_sha1, background):
    """Request rescan of existing result"""
    appcheck.rescan(id_or_sha1)
    click.echo("Requested rescan of {id_or_sha1}".format(id_or_sha1=id_or_sha1))
    if not background:
        _print_result(appcheck, id_or_sha1=id_or_sha1, json_output=False, wait=True)


def _print_result(appcheck, id_or_sha1, json_output, wait=True):
    wait_printed = False
    while True:
        try:
            data = appcheck.get_result(id_or_sha1=id_or_sha1)
            res = data.get('results', {})
            if wait and res['status'] == ProtecodeSC.STATUS_BUSY:
                if not wait_printed:
                    wait_printed = True
                    click.echo("Waiting for result for {id_or_sha1}"
                               .format(id_or_sha1=id_or_sha1))
                time.sleep(5)
                continue
            break
        except exceptions.ResultNotFound:
            click.echo("Result not found")
            return

    if json_output:
        click.echo(json.dumps(data))
        return

    summary = res['summary']
    filename = res.get('filename', "")
    sha1 = res.get('sha1sum')
    components = res.get('components', [])
    report_url = res.get('report_url')

    # Component analysis
    component_texts = set()
    for c in components:
        c_lib = c.get('lib')
        c_version = c.get('version')
        if c_version:
            c_version = clean_version(c_version)
            c_text = "{lib} ({version})".format(lib=c_lib, version=c_version)
        else:
            c_text = "{lib}".format(lib=c_lib)
        component_texts.add(c_text)
    # Number of vulnerable components
    vuln_components = sum([1 for c in components if c['vulns']])
    total_components = len(components)

    # License analysis
    lic_unknown = {'name': 'UNKNOWN'}
    licenses = [x.get('license', lic_unknown)['name'] for x in components]

    # Print output
    click.echo("Analysis results")
    click.echo("    File:   {name}".format(name=filename))
    click.echo("    SHA1:   {sha1}".format(sha1=sha1))
    if report_url:
        click.echo("    Report: {uri}".format(uri=report_url))

    if not res['status'] == ProtecodeSC.STATUS_READY:
        click.echo("Result not yet ready.")
        return

    if component_texts:
        click.echo()
        click.echo('Components:')
        click.echo('    ' + ' '.join(sorted(component_texts)))
    else:
        click.echo("No 3rd party or open source components detected.")

    if licenses:
        click.echo()
        click.echo('License analysis:')
        click.echo('    ' + ' '.join(sorted(set(licenses))))

    click.echo()
    verdict = summary['verdict']['short']
    if verdict == 'Verify':
        symbol = VERDICT_VERIFY_SYMBOL
    elif verdict == 'Vulns':
        symbol = VERDICT_FAIL_SYMBOL
    elif verdict == 'Pass':
        symbol = VERDICT_PASS_SYMBOL
    else:
        symbol = '??'
    click.echo('Vulnerability analysis:')
    click.echo(u'    {vuln} out of {total} components contain known '
               u'vulnerabilities {sym}'.format(vuln=vuln_components,
                                               total=total_components,
                                               sym=symbol))
    click.echo(u'    ' + summary['verdict']['detailed'])


@cli.add_command
@click.argument('file', 'file to analyze', nargs=-1, required=True, type=click.Path(exists=True))
@click.option('--group', help="Upload to group id GROUP (see group)",
              metavar="GROUP", type=int)
@click.option('--background/--wait', help="Scan in background; default: wait for results", default=False)
@click.command()
@use_appcheck
def scan(appcheck, file, group, background):
    """Analyze a file or directory.

    If a directory is analyzed, it will be compressed to a ZIP archive before
    upload.
    """

    file_count = len(file)
    click.echo('Uploading {count} objects...'.format(count=file_count))
    upload_shasums = []
    for i, f in enumerate(file):
        display_name = click.format_filename(f)
        click.echo(display_name)

        if os.path.isdir(f):
            # Upload directory as ZIP
            logger.info("Zipping directory...")
            zip_name = "{dirname}.zip".format(
                dirname=os.path.basename(display_name.rstrip(os.path.sep)))
            with NamedTemporaryFile() as tmp_file:
                with ZipFile(tmp_file.name, 'w') as zip_file:
                    zip_directory(f, zip_file)
                res = appcheck.upload_file(tmp_file.name,
                                           display_name=zip_name,
                                           group=group)
        else:
            # Regular file, upload as is
            res = appcheck.upload_file(f, group=group)

        if res['results']['status'] == ProtecodeSC.STATUS_READY:
            status = 'READY; scanned before'
        else:
            status = 'queued for scanning'
        report_url = res['results']['report_url']
        sha1_checksum = res['results']['sha1sum']
        upload_shasums.append(sha1_checksum)
        click.echo(" - SHA1: {sha1}".format(sha1=sha1_checksum))
        click.echo(" - {url} ({status})".format(url=report_url,
                                                status=status))

    if not background:
        click.echo()
        click.echo("="*50)
        for sha1 in upload_shasums:
            _print_result(appcheck, id_or_sha1=sha1, json_output=False,
                          wait=True)
            click.echo("="*50)


@cli.add_command
@click.argument('id_or_sha1', 'Analysis ID or file SHA1 hash')
@click.command()
@use_appcheck
def delete(appcheck, id_or_sha1):
    """Delete scan result"""

    click.confirm('Really delete all data for result?'.format(id=id_or_sha1), abort=True)
    try:
        appcheck.delete(id_or_sha1)
    except exceptions.ResultNotFound:
        click.echo("Result was not found")
        return


@cli.add_command
@click.command()
def login():
    """Save username/password and configure server address"""
    config = AppcheckClientConfig()
    if click.confirm("Use Protecode SC managed service https://protecode-sc.com/?"):
        config.set_appcheck_host(DEFAULT_APPCHECK_HOST)
    else:
        host = click.prompt("Enter URI (https://YOUR-APPLIANCE)")
        config.set_appcheck_host(host)
    update_login_credentials()


@cli.add_command
@click.command()
def logout():
    """Forget saved username and password"""
    config = AppcheckClientConfig()
    config.forget_credentials()


def update_login_credentials():
    username = click.prompt("Login username/email-address")
    password = click.prompt("Login password", hide_input=True)
    config = AppcheckClientConfig()
    if click.confirm('Save information and do not ask again?'):
        config.set_credentials(username, password)
        click.echo("Saved login details.")
    return username, password


def main(retries=2):
    # create logger
    logger = logging.getLogger('appcheck')
    logger.setLevel(logging.WARNING)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(levelname)s: %(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    try:
        for i in range(0, retries):
            try:
                cli(obj={})
            except exceptions.InvalidLoginError:
                click.echo("Login failed. Please log in again.")
                update_login_credentials()
        else:
            click.echo("Out of retries, aborting.")
    except KeyboardInterrupt:
        pass
    except exceptions.ConnectionFailure as e:
        click.echo(e)
        sys.exit(1)


if __name__ == '__main__':
    main()
