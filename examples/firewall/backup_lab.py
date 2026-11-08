"""Local encrypted-repository restore qualification for postgres_ha.py; no remote backend."""
import hashlib
import json
import pathlib
import secrets
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'charts/netcap-firewall-control/files'
POSTGRES = 'postgres:17.11@sha256:ff87138949ad9a46f32ff23bd6852b52ce024a13dffe9b4087be98292cdd3b4f'
RESTIC = 'restic/restic:0.18.1@sha256:39d9072fb5651c80d75c7a811612eb60b4c06b32ffe87c2e9f3c7222e1797e76'
ALPINE = 'alpine:3.23.2@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62'


def qualify(env, temp, config, password):
    prefix = 'ncf-backup-' + secrets.token_hex(4)
    volumes = {name: prefix + '-' + name for name in ['work', 'cache', 'repo', 'restored']}
    db_secret = temp / 'backup-database-secret'
    db_secret.mkdir(mode=0o755)
    (db_secret / 'ca.crt').write_text((config / 'tls.crt').read_text())
    repository_password = secrets.token_hex(32)
    wrong_password = secrets.token_hex(32)
    (db_secret / 'pg_service.conf').write_text(''.join(
        f'[{service}]\nhost=postgres\nport=5432\ndbname={database}\nuser=firewall\nsslmode=verify-full\nsslrootcert=/db/ca.crt\n'
        for service, database in [('backup', 'firewall'), ('fleet_restore', 'restored_fleet'), ('state_restore', 'restored_state')]))
    for path in db_secret.iterdir():
        path.chmod(0o644)

    def docker(*args, check=True, process_env=None, stdin=None):
        return subprocess.run(['docker', *args], text=True, capture_output=True, check=check, timeout=180,
                              env=process_env, input=stdin)

    def sql(database, statement):
        return docker('exec', env['PG_TEST_CONTAINER'], 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
                      '-U', 'firewall', '-d', database, '-Atc', statement).stdout.strip()

    def pg(*args, namespace='ncf_lab_fleet', limit='67108864', check=True):
        return docker('run', '--rm', '--name', prefix + '-pg', '--user', '10001:10001', '--read-only',
                      '--cap-drop=ALL', '--security-opt=no-new-privileges', '--network', env['COMPOSE_PROJECT_NAME'] + '_control',
                      '-v', str(SCRIPTS) + ':/scripts:ro', '-v', str(db_secret) + ':/db:ro',
                      '-v', volumes['work'] + ':/work', '-v', volumes['cache'] + ':/cache',
                      '-v', volumes['restored'] + ':/restored',
                      '-e', 'PGSERVICEFILE=/db/pg_service.conf', '-e', 'PGSERVICE=backup',
                      '-e', 'PGPASSWORD',
                      '-e', 'DATABASE_NAMESPACE=' + namespace, '-e', 'MAX_DUMP_BYTES=' + limit,
                      '-e', 'TMPDIR=/cache', '--entrypoint', '/bin/sh', POSTGRES, *args, check=check,
                      process_env=dict(env, PGPASSWORD=password))

    def restic(*args, host='netcap-lab-control-fleet', tag='netcap-control/lab/control/fleet/fleet-controller',
               password_file='/password/password', check=True):
        selected_password = wrong_password if password_file == '/password/wrong' else repository_password
        return docker('run', '--rm', '--interactive', '--name', prefix + '-restic', '--network=none', '--user', '10001:10001',
                      '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                      '--tmpfs', '/password:rw,noexec,nosuid,nodev,size=64k,mode=0700,uid=10001,gid=10001',
                      '-v', str(SCRIPTS) + ':/scripts:ro',
                      '-v', volumes['repo'] + ':/repo', '-v', volumes['work'] + ':/work',
                      '-v', volumes['cache'] + ':/cache', '-v', volumes['restored'] + ':/restored',
                      '-e', 'RESTIC_REPOSITORY=/repo', '-e', 'RESTIC_PASSWORD_FILE=' + password_file,
                      '-e', 'HOME=/cache', '-e', 'TMPDIR=/cache', '-e', 'RESTIC_CACHE_DIR=/cache',
                      '-e', 'BACKUP_HOST=' + host, '-e', 'BACKUP_TAG=' + tag,
                      '-e', 'KEEP_DAILY=1', '-e', 'KEEP_WEEKLY=0', '-e', 'KEEP_MONTHLY=0', '-e', 'PRUNE=true',
                      '--entrypoint', '/bin/sh', RESTIC, '-ec',
                      'umask 077; IFS= read -r secret; printf "%s" "$secret" > "$RESTIC_PASSWORD_FILE"; '
                      'unset secret; exec /bin/sh "$@"', 'sh', *args, check=check, stdin=selected_password + '\n')

    try:
        for name in volumes.values():
            docker('volume', 'create', '--label', 'netcap.backup-lab=' + prefix, name)
        mounts = [part for name, volume in volumes.items() for part in ['-v', volume + ':/' + name]]
        docker('run', '--rm', '--name', prefix + '-prepare', '--network=none', '--cap-drop=ALL', '--cap-add=CHOWN',
               *mounts, ALPINE, 'sh', '-ec', 'chmod 700 /work /cache /repo /restored; chown 10001:10001 /work /cache /repo /restored')
        restic('-ec', 'restic init --repository-version 2 >/cache/init.log 2>&1')
        bad_password = restic('-ec', 'restic snapshots --json', password_file='/password/wrong', check=False)
        assert bad_password.returncode != 0 and 'wrong password' in bad_password.stderr.lower()

        # A truncated archive must never become the upload input.
        limited = pg('/scripts/backup-dump.sh', limit='512', check=False)
        assert limited.returncode != 0
        pg('-ec', 'test ! -e /work/control.dump; test ! -e /work/control.dump.part')
        (db_secret / 'ca.crt').write_text('not a trusted certificate')
        assert pg('/scripts/backup-dump.sh', check=False).returncode != 0
        pg('-ec', 'test ! -e /work/control.dump; test ! -e /work/control.dump.part')
        (db_secret / 'ca.crt').write_text((config / 'tls.crt').read_text())

        host = 'netcap-lab-control-fleet'
        tag = 'netcap-control/lab/control/fleet/fleet-controller'
        restic('-ec', 'umask 077; printf sentinel > /work/sentinel')
        sentinels = set()
        for foreign_host, foreign_tag in [('netcap-unrelated-owner', tag), (host, 'unrelated-retention-sentinel')]:
            for year in ['2000', '2001']:
                restic('-ec', 'restic backup --quiet /work/sentinel --host "$1" --tag "$2" --time "$3"',
                       'sh', foreign_host, foreign_tag, year + '-01-01 00:00:00')
        for snapshot in json.loads(restic('-ec', 'restic snapshots --json').stdout):
            sentinels.add(snapshot['id'])
        assert len(sentinels) == 4

        counter_revision = hashlib.sha256(b'ha-revision').hexdigest()
        counter_group = hashlib.sha256(b'ha-group').hexdigest()
        queries = {
            'fleet': "SELECT convert_from(snapshot,'UTF8')::jsonb->'targets'->'waf1'->>'generation' FROM ncf_lab_fleet.fleet WHERE id=1",
            'state': f"SELECT count FROM ncf_lab_state.counters WHERE revision='{counter_revision}' AND grp='{counter_group}'",
        }
        restored = {}
        for family in ['fleet', 'state']:
            namespace = 'ncf_lab_' + family
            expected = sql('firewall', queries[family])
            assert expected and int(expected) > 0
            pg('/scripts/backup-dump.sh', namespace=namespace)
            if family == 'fleet':
                restic('-ec', 'restic backup --quiet /work/control.dump --host "$BACKUP_HOST" --tag "$BACKUP_TAG" --time "2000-01-01 00:00:00"')
                before_failure = {s['id'] for s in json.loads(restic('-ec', 'restic snapshots --json').stdout)}
                failed = restic('/scripts/backup-restic.sh', password_file='/password/wrong', check=False)
                assert failed.returncode != 0 and 'retention was not applied' in failed.stderr
                assert {s['id'] for s in json.loads(restic('-ec', 'restic snapshots --json').stdout)} == before_failure
                pg('-ec', 'test ! -e /work/control.dump')
                pg('/scripts/backup-dump.sh', namespace=namespace)
            family_host = 'netcap-lab-control-' + family
            family_tag = 'netcap-control/lab/control/' + family + '/' + ('fleet-controller' if family == 'fleet' else 'sharedstate')
            result = restic('/scripts/backup-restic.sh', host=family_host, tag=family_tag)
            assert 'Encrypted backup and scoped retention completed' in result.stdout
            pg('-ec', 'test ! -e /work/control.dump')
            snapshots = json.loads(restic('-ec', 'restic snapshots --json --host "$BACKUP_HOST" --tag "$BACKUP_TAG"',
                                          host=family_host, tag=family_tag).stdout)
            assert len(snapshots) == 1, 'scoped old snapshot was not forgotten'
            restic('-ec', 'restic restore latest --host "$BACKUP_HOST" --tag "$BACKUP_TAG" --target /restored >/cache/restore.log 2>&1',
                   host=family_host, tag=family_tag)
            sql('firewall', 'CREATE DATABASE restored_' + family)
            pg('-ec', 'pg_restore --exit-on-error --single-transaction --no-owner --no-acl --dbname="service=$1 sslmode=verify-full" /restored/work/control.dump',
               'sh', family + '_restore')
            actual = sql('restored_' + family, queries[family])
            assert actual == expected, (family, actual, expected)
            assert sql('firewall', queries[family]) == expected, 'source database changed during restore'
            restored[family] = int(actual)
        remaining = {s['id'] for s in json.loads(restic('-ec', 'restic snapshots --json').stdout)}
        assert sentinels <= remaining, 'foreign host/tag snapshots removed by retention/prune'
        restic('-ec', 'restic check --read-data >/cache/check.log 2>&1')
        for path in temp.rglob('*'):
            if path.is_file():
                contents = path.read_bytes()
                assert all(secret.encode() not in contents for secret in [password, repository_password, wrong_password]), \
                    'generated backup credential persisted in a host fixture file'
        return {'result': 'pass', 'repository': 'disposable local encrypted Docker volume, network disabled for all Restic calls',
                'images': {'postgres': POSTGRES, 'restic': RESTIC},
                'checks': ['exact chart scripts under UID 10001, read-only root and no capabilities',
                           'TLS-verified schema pg_dump and untrusted CA refusal', 'hard file-size failure leaves no upload artifact',
                           'wrong repository password rejected', 'encrypted backup/restore and full repository data check',
                           'DB password passed by environment; repository password piped into container tmpfs only',
                           'failed encrypted backup does not apply retention and removes plaintext archive',
                           'scoped retention/prune removes old owned snapshot and preserves four foreign snapshots',
                           'restored fleet generation and shared count equal source; source unchanged'],
                'restored_sql_values': restored,
                'boundary': 'no remote repository, cloud credential, estate resource or scheduled production job exercised'}
    finally:
        for suffix in ['pg', 'restic', 'prepare']:
            docker('rm', '-f', prefix + '-' + suffix, check=False)
        for volume in volumes.values():
            docker('volume', 'rm', volume, check=False)
