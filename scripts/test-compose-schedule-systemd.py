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
    event('admission')
    spec = importlib.util.spec_from_file_location('observer', {str(ROOT / 'scripts/observe-restic-backups.py')!r})
    observer = importlib.util.module_from_spec(spec); spec.loader.exec_module(observer)
    try:
        timer = {cls.prefix!r} + '-restic-daily.timer'
        raw = subprocess.check_output(['systemctl', 'show', '--property=ActiveState,SubState,Unit,LastTriggerUSec,NextElapseUSecRealtime', timer], text=True)
        properties = observer.parse_properties(raw)
        properties['Unit'] = properties.get('Unit', '').replace({cls.prefix!r}, 'home-lab')
        observer.validate_timer_state('home-lab-restic-daily.timer', properties, scheduled_deployment=True)
        for suffix in ('restic-daily.target', 'restic-daily-local.service', 'restic-daily-proton.service'):
            unit = {cls.prefix!r} + '-' + suffix
            raw = subprocess.check_output(['systemctl', 'show', '--property=ActiveState,SubState,Result', unit], text=True)
            observer.validate_unit_state(unit, observer.parse_properties(raw), routine=True)
    except observer.ObservationError:
        event('refused'); sys.exit(1)
    event('deploy')
else:
    event(phase + '-start'); time.sleep(0.2)
    result = int((work / (phase + '-result')).read_text())
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
        for phase in ("local", "proton"):
            ordering = ("Before=home-lab-restic-daily-proton.service" if phase == "local" else
                        "Requires=home-lab-restic-daily-local.service\nAfter=home-lab-restic-daily-local.service")
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
        self.assertEqual(self.observed_events(), ["local-start", "local-end", "proton-start", "proton-end"])

    def test_timer_runs_deployment_only_after_both_backup_phases_finish(self):
        self.assertEqual(self.start_scheduled(), ["local-start", "local-end", "proton-start", "proton-end", "admission", "deploy"])
        # systemd removes this run's credential/runtime scope when the oneshot exits.
        deadline = time.monotonic() + 5
        runtime = Path("/run") / (self.prefix + "-compose-deploy")
        while runtime.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertFalse(runtime.exists())
        self.assertFalse((Path('/run/credentials') / (self.prefix + '-compose-routine.service')).exists())

    def test_terminal_proton_failure_still_crosses_existing_routine_admission(self):
        self.work.joinpath("proton-result").write_text("1")
        self.assertEqual(self.start_scheduled(), ["local-start", "local-end", "proton-start", "proton-end", "admission", "deploy"])

    def test_local_failure_is_refused_by_existing_admission_not_silently_bypassed(self):
        self.work.joinpath("local-result").write_text("1")
        events = self.start_scheduled()
        self.assertEqual(events, ["local-start", "local-end", "admission", "refused"])


if __name__ == "__main__":
    if (platform.system() != "Linux" or os.geteuid() != 0
            or os.environ.get("HOME_LAB_SYSTEMD_TEST_DISPOSABLE") != "true"
            or Path("/srv/docker-compose/current").exists()):
        raise SystemExit("native systemd fixture requires an explicitly disposable Linux host, never production")
    unittest.main()
