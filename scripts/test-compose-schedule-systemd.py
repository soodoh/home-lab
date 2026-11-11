#!/usr/bin/env python3
"""Qualify native timer/dependency behavior only on an explicitly disposable Linux host.

Never run this on either managed home-lab host. Units use a unique test prefix,
synthetic backup commands and the real backup unit-state admission function.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parent.parent


def systemctl(*arguments, check=True):
    return subprocess.run(["systemctl", *arguments], text=True, capture_output=True, check=check)


class ScheduleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Credential sources must be outside PrivateTmp's hidden /tmp and /var/tmp.
        cls.temporary = tempfile.TemporaryDirectory(prefix="compose-systemd-", dir="/var/lib")
        cls.work = Path(cls.temporary.name)
        cls.prefix = "test-compose-" + uuid.uuid4().hex[:12]
        cls.units = []
        cls.addClassCleanup(cls.cleanup)
        cls.events = cls.work / "events"
        cls.environment = Environment(undefined=StrictUndefined)
        cls.variables = {
            "compose_schedule_age_key": str(cls.work / "age-key"),
            "compose_schedule_controller_root": str(ROOT),
            "compose_schedule_venv": str(cls.work / "venv"),
            "compose_schedule_collections": str(cls.work / "collections"),
            "compose_schedule_bin": str(cls.work / "bin"),
            "restic_systemd": {"daily_calendar": "2099-01-01 05:00:00"},
            "restic_backup_daily_timer_destination": "home-lab-morning.target",
        }
        (cls.work / "age-key").write_text("SYNTHETIC\n")
        (cls.work / "age-key").chmod(0o400)
        (cls.work / "venv/bin").mkdir(parents=True)
        helper = cls.work / "fixture.py"
        helper.write_text(f"""#!{sys.executable}
import importlib.util, os, pathlib, subprocess, sys, time
work = pathlib.Path({str(cls.work)!r})
phase = sys.argv[1]
def event(value):
    with (work / 'events').open('a') as output: output.write(value + '\\n')
if phase == 'deploy':
    assert sys.argv[2:] == [{str(ROOT / 'ansible/playbooks/deploy-compose-automatic.yml')!r}, '--limit', 'docker-host', '-e', 'ansible_connection=local', '-e', 'ansible_user=root', '-e', 'ansible_become=false']
    assert pathlib.Path(os.environ['SOPS_AGE_KEY_FILE']).read_text() == 'SYNTHETIC\\n'
    # Exercise real local-connection module scratch under ProtectHome, not only
    # the stand-in deployment executable. A default /root/.ansible/tmp is refused.
    result = subprocess.run([sys.executable, '-m', 'ansible.cli.adhoc', 'localhost',
                             '-i', 'localhost,', '-c', 'local', '-m', 'ansible.builtin.setup'],
                            text=True, capture_output=True)
    if result.returncode:
        print(result.stdout, result.stderr, flush=True); sys.exit(result.returncode)
    assert pathlib.Path(os.environ['ANSIBLE_REMOTE_TEMP']).is_relative_to(pathlib.Path(os.environ['TMPDIR']))
    event('admission')
    spec = importlib.util.spec_from_file_location('observer', {str(ROOT / 'scripts/observe-restic-backups.py')!r})
    observer = importlib.util.module_from_spec(spec); spec.loader.exec_module(observer)
    try:
        timer = {cls.prefix!r} + '-restic-daily.timer'
        raw = subprocess.check_output(['systemctl', 'show', '--property=ActiveState,SubState,Unit,LastTriggerUSec,NextElapseUSecRealtime', timer], text=True)
        properties = observer.parse_properties(raw)
        properties['Unit'] = properties.get('Unit', '').replace({cls.prefix!r}, 'home-lab')
        observer.validate_timer_state('home-lab-restic-daily.timer', properties, scheduled_deployment=True)
        for suffix in ('restic-daily.target', 'restic-daily-local.service'):
            unit = {cls.prefix!r} + '-' + suffix
            raw = subprocess.check_output(['systemctl', 'show', '--property=ActiveState,SubState,Result', unit], text=True)
            observer.validate_unit_state(unit, observer.parse_properties(raw), routine=True)
    except observer.ObservationError:
        event('refused'); sys.exit(1)
    event('deploy')
else:
    event(phase + '-start'); time.sleep(0.2)
    result = int((work / (phase + '-result')).read_text())
    if phase == 'proton' and result == 0:
        deadline = time.monotonic() + 30
        while not (work / 'release-copy').exists() and time.monotonic() < deadline:
            time.sleep(0.05)
    event(phase + '-end'); sys.exit(result)
""")
        executable = cls.work / "venv/bin/ansible-playbook"
        executable.write_text(f'#!/bin/sh\nexec {sys.executable} {helper} deploy "$@"\n')
        executable.chmod(0o755)
        for unit in ("home-lab-morning.target", "home-lab-compose-routine.service"):
            template = ROOT / f"ansible/roles/compose_schedule/templates/{unit}.j2"
            rendered = cls.environment.from_string(template.read_text()).render(cls.variables)
            cls.install(unit, rendered)
        for unit in ("home-lab-restic-daily.target", "home-lab-restic-daily.timer"):
            template = ROOT / f"ansible/roles/restic_backup/templates/{unit}.j2"
            rendered = cls.environment.from_string(template.read_text()).render(cls.variables)
            if unit.endswith(".timer"):
                rendered += "\n[Timer]\nOnActiveSec=0.2\nAccuracySec=1ms\n"
            cls.install(unit, rendered)
        template = ROOT / 'ansible/roles/restic_backup/templates/home-lab-restic-replication.target.j2'
        cls.install('home-lab-restic-replication.target', template.read_text())
        cls.install('home-lab-restic-daily-nfs.service', '[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
        for phase in ("local", "proton"):
            ordering = 'OnSuccess=home-lab-restic-replication.target' if phase == 'local' else ''
            cls.install(f"home-lab-restic-daily-{phase}.service", f"""[Unit]
Description=Synthetic {phase} backup phase
{ordering}
[Service]
Type=oneshot
ExecStart={sys.executable} {helper} {phase}
""")
        systemctl("daemon-reload")
        subprocess.run(["systemd-analyze", "verify", *map(str, cls.units)], check=True)

    @classmethod
    def install(cls, name, definition):
        path = Path("/run/systemd/system") / name.replace("home-lab-", cls.prefix + "-")
        path.write_text(definition.replace("home-lab-", cls.prefix + "-"))
        cls.units.append(path)

    @classmethod
    def cleanup(cls):
        for path in cls.units:
            systemctl("stop", path.name, check=False)
            systemctl("reset-failed", path.name, check=False)
            if path.name.endswith('.timer'):
                systemctl('disable', '--runtime', path.name, check=False)
            path.unlink(missing_ok=True)
        systemctl("daemon-reload")
        cls.temporary.cleanup()

    def setUp(self):
        for path in self.units:
            systemctl("stop", path.name, check=False)
            systemctl("reset-failed", path.name, check=False)
        self.events.unlink(missing_ok=True)
        self.work.joinpath('release-copy').unlink(missing_ok=True)
        for phase in ("local", "proton"):
            self.work.joinpath(phase + "-result").write_text("0")

    def observed_events(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def start_scheduled(self):
        timer = self.prefix + "-restic-daily.timer"
        self.assertEqual(systemctl("show", "--property=Unit", timer).stdout.strip(),
                         "Unit=" + self.prefix + "-morning.target")
        systemctl("start", timer)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            values = self.observed_events()
            if "deploy" in values or "refused" in values:
                systemctl("stop", timer)
                return values
            routine = self.prefix + '-compose-routine.service'
            if systemctl('is-failed', routine, check=False).returncode == 0:
                details = systemctl('show', '--property=LoadCredential,ActiveState,Result,ExecMainStatus', routine).stdout
                journal = subprocess.run(['journalctl', '--no-pager', '--unit', routine, '-n', '30'],
                                         text=True, capture_output=True).stdout
                self.fail(f'scheduled fixture failed before admission: {values}\n{details}\n{journal}')
            time.sleep(0.1)
        self.fail(f"native scheduled workflow did not reach admission: {self.observed_events()}")

    def test_reload_and_detach_preserve_active_backup_timer_without_starting_work(self):
        path = Path('/run/systemd/system') / (self.prefix + '-restic-daily.timer')
        original = path.read_text()
        timer = self.prefix + '-restic-daily.timer'
        path.write_text(original.replace('OnActiveSec=0.2\n', ''))
        try:
            systemctl('daemon-reload')
            systemctl('start', timer)
            self.assertEqual(systemctl('show', '--property=Unit', timer).stdout.strip(),
                             'Unit=' + self.prefix + '-morning.target')
            self.assertEqual(systemctl('is-active', timer).stdout.strip(), 'active')
            path.write_text(path.read_text().replace(self.prefix + '-morning.target',
                                                     self.prefix + '-restic-daily.target'))
            systemctl('daemon-reload')
            self.assertEqual(systemctl('show', '--property=Unit', timer).stdout.strip(),
                             'Unit=' + self.prefix + '-restic-daily.target')
            self.assertIn('2099-01-01', systemctl('show', '--property=TimersCalendar', timer).stdout)
            self.assertEqual(self.observed_events(), [])
        finally:
            systemctl('stop', timer, check=False)
            path.write_text(original)
            systemctl('daemon-reload')

    def test_shared_ansible_renderer_preserves_scheduling_until_explicit_switch(self):
        # The real renderer has a fixed production resource name. Only adopt it
        # in this disposable test host after proving no such unit already exists.
        names = ['home-lab-restic-daily.target', 'home-lab-morning.target', 'home-lab-restic-daily.timer']
        for name in names:
            self.assertEqual(systemctl('show', '--property=LoadState', name).stdout.strip(), 'LoadState=not-found')
            self.assertFalse(Path('/etc/systemd/system', name).exists())
        for name in names:
            path = Path('/run/systemd/system', name)
            self.units.append(path)
            if name.endswith('.target'):
                path.write_text('[Unit]\nDescription=Synthetic timer renderer target\n')
            else:
                variables = {**self.variables, 'restic_backup_daily_timer_destination': 'home-lab-restic-daily.target'}
                template = ROOT / 'ansible/roles/restic_backup/templates/home-lab-restic-daily.timer.j2'
                path.write_text(self.environment.from_string(template.read_text()).render(variables))
        self.units.append(Path('/etc/systemd/system/home-lab-restic-daily.timer'))
        systemctl('daemon-reload')
        systemctl('enable', '--runtime', 'home-lab-restic-daily.timer')
        systemctl('start', 'home-lab-restic-daily.timer')
        play = self.work / 'render-timer.yml'
        play.write_text(json.dumps([{'name': 'Exercise the shared native renderer', 'hosts': 'localhost',
                                    'gather_facts': False, 'vars': {'restic_systemd': self.variables['restic_systemd'],
                                                                'compose_schedule_enabled': True},
                                    'tasks': [{'ansible.builtin.include_role': {'name': 'restic_backup', 'tasks_from': 'daily-timer'}},
                                              {'ansible.builtin.meta': 'flush_handlers'}]}]))
        config = self.work / 'ansible.cfg'
        config.write_text(f'[defaults]\nroles_path={ROOT / "ansible/roles"}\nlocal_tmp={self.work / "ansible"}\n')
        environment = {**os.environ, 'ANSIBLE_CONFIG': str(config), 'PYTHONDONTWRITEBYTECODE': '1'}
        arguments = [sys.executable, '-m', 'ansible.cli.playbook', '-i', 'localhost,', '-c', 'local', str(play)]
        for replacement, expected in [(None, 'home-lab-restic-daily.target'),
                                      ('home-lab-morning.target', 'home-lab-morning.target'),
                                      (None, 'home-lab-morning.target'),
                                      ('home-lab-restic-daily.target', 'home-lab-restic-daily.target')]:
            extra = [] if replacement is None else ['-e', json.dumps({'restic_backup_daily_timer_target': replacement})]
            result = subprocess.run(arguments + extra, env=environment, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(systemctl('show', '--property=Unit', names[-1]).stdout.strip(), 'Unit=' + expected)
            self.assertEqual(systemctl('is-active', names[-1]).stdout.strip(), 'active')
            self.assertEqual(systemctl('is-enabled', names[-1]).stdout.strip(), 'enabled-runtime')
            self.assertIn('2099-01-01', systemctl('show', '--property=TimersCalendar', names[-1]).stdout)
        before = Path('/etc/systemd/system/home-lab-restic-daily.timer').read_bytes()
        result = subprocess.run(arguments + ['-e', json.dumps({'restic_backup_daily_timer_target': 'unknown.target'})],
                                env=environment, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Only the backup-only or approved scheduled-deployment workflow', result.stdout)
        timer_path = Path('/etc/systemd/system/home-lab-restic-daily.timer')
        self.assertEqual(timer_path.read_bytes(), before)
        unknown = before.replace(b'Unit=home-lab-restic-daily.target', b'Unit=unknown.target')
        timer_path.write_bytes(unknown)
        systemctl('daemon-reload')
        result = subprocess.run(arguments, env=environment, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Inspect unexpected backup scheduling', result.stdout)
        self.assertEqual(timer_path.read_bytes(), unknown)
        self.assertEqual(self.observed_events(), [])

    def test_manual_backup_has_no_deployment_side_effect(self):
        systemctl("start", self.prefix + "-restic-daily.target")
        events = self.observed_events()
        self.assertEqual([e for e in events if e.startswith('local')], ['local-start', 'local-end'])
        self.assertNotIn('admission', events)
        self.assertNotIn('deploy', events)

    def test_timer_runs_deployment_after_local_capture_while_copy_is_active(self):
        events = self.start_scheduled()
        self.assertEqual([e for e in events if not e.startswith('proton')], ['local-start', 'local-end', 'admission', 'deploy'])
        self.assertNotIn('proton-end', events)
        self.assertEqual(systemctl('show', '--property=ActiveState', self.prefix + '-restic-daily-proton.service').stdout.strip(),
                         'ActiveState=activating')
        self.work.joinpath('release-copy').touch()
        # systemd removes this run's credential/runtime scope when the oneshot exits.
        deadline = time.monotonic() + 5
        runtime = Path("/run") / (self.prefix + "-compose-deploy")
        while runtime.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertFalse(runtime.exists())
        self.assertFalse((Path('/run/credentials') / (self.prefix + '-compose-routine.service')).exists())

    def test_terminal_proton_failure_still_crosses_existing_routine_admission(self):
        self.work.joinpath("proton-result").write_text("1")
        events = self.start_scheduled()
        self.assertEqual([e for e in events if not e.startswith('proton')], ['local-start', 'local-end', 'admission', 'deploy'])

    def test_local_failure_is_refused_by_existing_admission_not_silently_bypassed(self):
        self.work.joinpath("local-result").write_text("1")
        events = self.start_scheduled()
        self.assertEqual(events, ["local-start", "local-end", "admission", "refused"])


class ReplicaSandboxTests(unittest.TestCase):
    """Exercise real mount admission inside both rendered replica sandboxes."""

    def setUp(self):
        # PrivateTmp hides /tmp. All service inputs are synthetic and copied here.
        self.temporary = tempfile.TemporaryDirectory(prefix='restic-systemd-', dir='/var/lib')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        nobody = pwd.getpwnam('nobody')
        os.chown(self.work, nobody.pw_uid, nobody.pw_gid)
        self.units = []
        self.addCleanup(self.cleanup_units)
        self.games = self.work / 'games'
        self.repository = self.games / 'restic/home-lab'
        for folder in (self.repository / 'locks', self.work / 'nfs', self.work / 'app-state',
                       self.work / 'compose', self.work / 'config', self.work / 'proton-cache',
                       self.work / 'local-cache'):
            folder.mkdir(parents=True)
            os.chown(folder, nobody.pw_uid, nobody.pw_gid)
        shutil.copyfile(ROOT / 'scripts/restic-backup', self.work / 'runner.py')
        observed = json.loads(subprocess.check_output([
            'findmnt', '--json', '--nofsroot', '--target', str(self.repository),
            '--output', 'TARGET,FSTYPE,SOURCE,UUID'], text=True))['filesystems'][0]
        self.assertEqual(observed['fstype'], 'ext4', 'native fixture requires an ext4 backing filesystem')
        self.assertTrue(observed['uuid'], 'native fixture requires a UUID-backed filesystem')
        self.identity = observed
        self.policy = {'repositories': {'games': {
            'path': str(self.repository), 'filesystem': observed['fstype'],
            'filesystem_uuid': observed['uuid'],
        }}}
        self.policy_path = self.work / 'policy.json'
        self.policy_path.write_text(json.dumps(self.policy))

    def cleanup_units(self):
        for path in self.units:
            systemctl('stop', path.name, check=False)
            systemctl('reset-failed', path.name, check=False)
            path.unlink(missing_ok=True)
        systemctl('daemon-reload')

    def verify_replica(self, destination):
        result_path = self.work / ('local-cache' if destination == 'nfs' else 'proton-cache') / 'result'
        helper = self.work / 'verify'
        helper.write_text(f'''#!{sys.executable}
import json, os, pathlib, runpy, stat
runner = runpy.run_path({str(self.work / 'runner.py')!r})
# Only the Restic repository-open boundary is synthetic: mount admission is real.
runner['preflight'].__globals__['verify_repository'] = lambda *_: {{'chunker_polynomial': 'fixture'}}
result = pathlib.Path({str(result_path)!r})
try:
    runner['preflight'](json.loads(pathlib.Path({str(self.policy_path)!r}).read_text()), ['games'])
except runner['WorkflowError'] as error:
    result.write_text(str(error))
    raise SystemExit(1)
device = {self.identity['source']!r}
assert stat.S_ISBLK(os.stat(device).st_mode), 'device metadata must remain visible'
try:
    descriptor = os.open(device, os.O_RDONLY)
except PermissionError:
    pass
else:
    os.close(descriptor)
    raise AssertionError('raw-device access must remain denied, even for root')
node = result.with_name('device-node')
try:
    os.mknod(node, stat.S_IFCHR | 0o600, os.makedev(1, 3))
except PermissionError:
    pass
else:
    node.unlink()
    raise AssertionError('device creation must remain denied, even for root')
result.write_text('verified')
''')
        helper.chmod(0o755)
        variables = {'restic_systemd': {
            'runner_path': str(helper), 'games_mountpoint': str(self.games),
            'games_repository_path': str(self.repository), 'nfs_mountpoint': str(self.work / 'nfs'),
            'nfs_repository_path': str(self.work / 'nfs'),
        }}
        template = ROOT / f'ansible/roles/restic_backup/templates/home-lab-restic-daily-{destination}.service.j2'
        definition = Environment(undefined=StrictUndefined).from_string(template.read_text()).render(variables)
        # Preserve the non-root replica boundary without creating a host account.
        definition = definition.replace('User=restic-proton', 'User=nobody').replace(
            'Group=restic-proton', f'Group={pwd.getpwnam("nobody").pw_gid}')
        for source, target in (
            ('/srv/home-lab-state', 'app-state'), ('/etc/docker-compose', 'compose'),
            ('/etc/home-lab/restic', 'config'), ('/var/lib/restic-proton', 'proton-cache'),
            ('/var/cache/home-lab-restic', 'local-cache'),
        ):
            definition = definition.replace(source, str(self.work / target))
        unit = Path('/run/systemd/system') / ('test-restic-' + uuid.uuid4().hex + '.service')
        self.units.append(unit)
        unit.write_text(definition)
        systemctl('daemon-reload')
        subprocess.run(['systemd-analyze', 'verify', str(unit)], check=True)
        for field, replacement in ((None, None), ('filesystem_uuid', '00000000-0000-0000-0000-000000000000'),
                                   ('filesystem', 'xfs')):
            with self.subTest(destination=destination, invalid_field=field):
                policy = json.loads(json.dumps(self.policy))
                if field:
                    policy['repositories']['games'][field] = replacement
                self.policy_path.write_text(json.dumps(policy))
                result_path.unlink(missing_ok=True)
                started = systemctl('start', unit.name, check=False)
                if not result_path.exists():
                    self.fail(subprocess.check_output([
                        'journalctl', '--no-pager', '--unit', unit.name, '-n', '30'], text=True))
                self.assertEqual(result_path.read_text(), 'source_mount_identity' if field else 'verified')
                self.assertEqual(started.returncode == 0, field is None)
                systemctl('reset-failed', unit.name, check=False)

    def test_nfs_sandbox_accepts_only_the_expected_source_without_raw_device_access(self):
        self.verify_replica('nfs')

    def test_proton_sandbox_accepts_only_the_expected_source_without_raw_device_access(self):
        self.verify_replica('proton')


if __name__ == "__main__":
    if (platform.system() != "Linux" or os.geteuid() != 0
            or os.environ.get("HOME_LAB_SYSTEMD_TEST_DISPOSABLE") != "true"
            or Path("/srv/docker-compose/current").exists()):
        raise SystemExit("native systemd fixture requires an explicitly disposable Linux host, never production")
    unittest.main()
