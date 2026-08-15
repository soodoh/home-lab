#!/usr/bin/env python3
"""Safety tests for exact stopped runtime container removal."""

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/controller/remove-vm-100-stopped-runtime-containers.py"
spec = importlib.util.spec_from_file_location("runtime_removal", SCRIPT)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


class RuntimeRemovalTests(unittest.TestCase):
    def test_running_inventory_requires_41_unique_compose_services(self):
        values = [{"Id": f"{index:064x}", "State": {"Running": True}, "Config": {"Labels": {"com.docker.compose.project": "docker-compose", "com.docker.compose.service": f"service-{index}"}}} for index in range(41)]
        self.assertEqual(len(module.running_inventory(values)), 41)
        values[0]["Config"]["Labels"]["com.docker.compose.project"] = "other"
        with self.assertRaises(ValueError): module.running_inventory(values)

    def test_request_and_evidence_schemas_are_strict(self):
        for name in ("stopped-runtime-removal-request", "stopped-runtime-removal-evidence"):
            schema = json.loads((ROOT / f"infrastructure/vm-100/{name}.schema.json").read_text())
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["required"]), set(schema["properties"]))

    def test_mutation_is_exact_and_never_deletes_volumes(self):
        source = SCRIPT.read_text()
        self.assertIn('["/usr/bin/docker", "rm", "--", *sorted(expected)]', source)
        self.assertNotIn("docker container prune", source)
        self.assertNotIn('"--volumes"', source)
        self.assertNotIn('"-v"', source)
        self.assertIn("attached runtime volume was not preserved", source)


if __name__ == "__main__": unittest.main()
