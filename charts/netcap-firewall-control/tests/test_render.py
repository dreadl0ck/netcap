"""Helm control-plane singleton, storage and Secret boundary contract."""
import pathlib
import subprocess
import unittest

import yaml

CHART = pathlib.Path(__file__).resolve().parents[1]
ARGS = ['--set', 'enabled=true', '--set', 'configSecretName=bootstrap',
        '--set', 'credentialsSecretName=tokens', '--set', 'tlsSecretName=control-tls']


def render(*args, success=True):
    r = subprocess.run(['helm', 'template', 'lab', str(CHART), '--kube-version', '1.32.2', *args],
                       text=True, capture_output=True)
    if not success:
        assert r.returncode != 0, 'unsafe control values accepted'
        return
    assert r.returncode == 0, r.stderr
    return [d for d in yaml.safe_load_all(r.stdout) if d]


class ControlContract(unittest.TestCase):
    def test_backup_cronjob_security_and_retention_scope(self):
        pg = ['--set', 'persistence.backend=postgres', '--set', 'replicaCount=2',
              '--set', 'persistence.postgres.databaseURLEnv=CONTROL_DATABASE_URL',
              '--set', 'persistence.postgres.databaseNamespace=ncf_fleet']
        backup = ['--set', 'backup.enabled=true', '--set', 'backup.scope=cluster-one',
                  '--set', 'backup.databaseSecretName=backup-db', '--set', 'backup.repositorySecretName=backup-repo',
                  '--set', 'backup.passwordSecretName=backup-password']
        self.assertNotIn('CronJob', {d['kind'] for d in render(*ARGS, *pg)})
        docs = render(*ARGS, *pg, *backup)
        self.assertFalse({'Secret', 'Role', 'RoleBinding', 'ClusterRole'} & {d['kind'] for d in docs})
        cron = next(d for d in docs if d['kind'] == 'CronJob')
        self.assertEqual(cron['spec']['concurrencyPolicy'], 'Forbid')
        self.assertEqual(cron['spec']['timeZone'], 'Etc/UTC')
        job = cron['spec']['jobTemplate']['spec']
        self.assertEqual(job['backoffLimit'], 1)
        self.assertEqual(job['activeDeadlineSeconds'], 900)
        self.assertEqual(job['ttlSecondsAfterFinished'], 3600)
        pod = job['template']['spec']
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(pod['restartPolicy'], 'Never')
        self.assertEqual(pod['securityContext']['runAsUser'], 10001)
        stages = [*pod['initContainers'], *pod['containers']]
        for stage in stages:
            self.assertTrue(stage['securityContext']['readOnlyRootFilesystem'])
            self.assertFalse(stage['securityContext']['allowPrivilegeEscalation'])
            self.assertEqual(stage['securityContext']['capabilities']['drop'], ['ALL'])
            self.assertIn('ephemeral-storage', stage['resources']['limits'])
        self.assertTrue(stages[0]['image'].startswith('postgres:17.11@sha256:'))
        self.assertTrue(stages[1]['image'].startswith('restic/restic:0.18.1@sha256:'))
        dump_env = {e['name']: e['value'] for e in stages[0]['env']}
        env = {e['name']: e['value'] for e in stages[1]['env']}
        self.assertEqual(dump_env['PGSERVICEFILE'], '/db/pg_service.conf')
        self.assertEqual(dump_env['DATABASE_NAMESPACE'], 'ncf_fleet')
        self.assertEqual(dump_env['MAX_DUMP_BYTES'], '67108864')
        self.assertEqual(env['RESTIC_PASSWORD_FILE'], '/password/password')
        self.assertEqual(env['BACKUP_HOST'], 'netcap-cluster-one-default-lab')
        self.assertEqual(env['BACKUP_TAG'], 'netcap-control/cluster-one/default/lab/fleet-controller')
        self.assertEqual(env['PRUNE'], 'false')
        self.assertEqual(stages[1]['envFrom'], [{'secretRef': {'name': 'backup-repo'}}])
        self.assertNotIn('database', {v['name'] for v in stages[1]['volumeMounts']})
        self.assertFalse(any('hostPath' in v or 'persistentVolumeClaim' in v for v in pod['volumes']))
        self.assertEqual(next(v for v in pod['volumes'] if v['name'] == 'work')['emptyDir']['sizeLimit'], '128Mi')
        scripts = next(d for d in docs if d['kind'] == 'ConfigMap')
        self.assertTrue(scripts['immutable'])
        self.assertIn('sslmode=verify-full', scripts['data']['dump.sh'])
        self.assertIn('ulimit -f', scripts['data']['dump.sh'])
        self.assertIn('restic forget --quiet --host "$BACKUP_HOST" --tag "$BACKUP_TAG"', scripts['data']['restic.sh'])
        self.assertNotIn('restic prune', scripts['data']['restic.sh'])
        self.assertNotIn('restic init', scripts['data']['restic.sh'])
        for override in ['enabled=false', 'backup.scope=', 'backup.scope=other/scope',
                         'backup.databaseSecretName=', 'backup.repositorySecretName=', 'backup.passwordSecretName=',
                         'backup.retention.keepDaily=0', 'backup.retention.prune=invalid', 'backup.maxDumpBytes=513',
                         'backup.repositoryURL=s3:plaintext', 'backup.retention.global=true']:
            render(*ARGS, *pg, *backup, '--set', override, success=False)
        render(*ARGS, *backup, success=False)
        old = subprocess.run(['helm', 'template', 'lab', str(CHART), '--kube-version', '1.25.0',
                              *ARGS, *pg, *backup], text=True, capture_output=True)
        self.assertNotEqual(old.returncode, 0)
        self.assertIn('timeZone requires Kubernetes 1.27+', old.stderr)

    def test_disabled_and_secret_gates(self):
        self.assertEqual(render(), [])
        render('--set', 'enabled=true', success=False)
        for override in ['tlsSecretName=', 'credentialsSecretName=', 'configSecretName=', 'replicaCount=2', 'token=plaintext']:
            render(*ARGS, '--set', override, success=False)

    def test_fenced_singleton_and_existing_claim(self):
        for service in ['fleet-controller', 'sharedstate']:
            docs = render(*ARGS, '--set', 'service=' + service)
            deployment = next(d for d in docs if d['kind'] == 'Deployment')
            self.assertEqual(deployment['spec']['replicas'], 1)
            self.assertEqual(deployment['spec']['strategy'], {'type': 'Recreate'})
            pod = deployment['spec']['template']['spec']
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertTrue(pod['securityContext']['runAsNonRoot'])
            c = pod['containers'][0]
            self.assertEqual(c['args'][0], service)
            self.assertEqual(c['envFrom'], [{'secretRef': {'name': 'tokens'}}])
            self.assertEqual(c['securityContext']['capabilities']['drop'], ['ALL'])
            self.assertEqual(next(d for d in docs if d['kind'] == 'PersistentVolumeClaim')['metadata']['annotations']['helm.sh/resource-policy'], 'keep')
        self.assertNotIn('PersistentVolumeClaim', {d['kind'] for d in render(*ARGS, '--set', 'storage.existingClaim=existing')})

    def test_postgres_active_active_has_no_local_state(self):
        pg = ['--set', 'persistence.backend=postgres', '--set', 'replicaCount=2',
              '--set', 'persistence.postgres.databaseURLEnv=CONTROL_DATABASE_URL',
              '--set', 'persistence.postgres.databaseNamespace=ncf_fleet']
        for service in ['fleet-controller', 'sharedstate']:
            docs = render(*ARGS, *pg, '--set', 'service=' + service)
            self.assertNotIn('PersistentVolumeClaim', {d['kind'] for d in docs})
            deploy = next(d for d in docs if d['kind'] == 'Deployment')
            self.assertEqual(deploy['spec']['replicas'], 2)
            self.assertEqual(deploy['spec']['strategy']['type'], 'RollingUpdate')
            pod = deploy['spec']['template']['spec']
            self.assertNotIn('state', {v['name'] for v in pod['volumes']})
            self.assertNotIn('state', {v['name'] for v in pod['containers'][0]['volumeMounts']})
            self.assertEqual(pod['containers'][0]['envFrom'], [{'secretRef': {'name': 'tokens'}}])
        for override in ['replicaCount=1', 'storage.existingClaim=sqlite-data',
                         'persistence.postgres.databaseURLEnv=', 'persistence.postgres.databaseNamespace=',
                         'persistence.postgres.databaseNamespace=public', 'persistence.postgres.databaseNamespace=pg_temp',
                         'persistence.postgres.databaseURL=postgres://plaintext']:
            render(*ARGS, *pg, '--set', override, success=False)


if __name__ == '__main__':
    unittest.main()
