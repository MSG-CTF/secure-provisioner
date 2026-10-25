"""Guest profiles are content addressed; Git must preserve their exact bytes."""
import hashlib
import json
from pathlib import Path
import unittest


class VMProfileBytesTest(unittest.TestCase):
    def test_profile_content_matches_trusted_filename(self):
        profiles = list((Path(__file__).parent / "vm" / "profiles").glob("*.json"))
        self.assertTrue(profiles)
        for profile in profiles:
            with self.subTest(profile=profile.name):
                self.assertEqual(hashlib.sha256(profile.read_bytes()).hexdigest(), profile.stem)

    def test_example_target_uses_the_same_images_as_its_profile(self):
        directory = Path(__file__).parent / "vm"
        targets = json.loads((directory / "targets.example.json").read_text())
        for target in targets["targets"]:
            profile = directory / "profiles" / (target["profile_sha256"] + ".json")
            services = json.loads(profile.read_text())["compose"]["services"]
            self.assertEqual(
                {container["name"]: container["image"] for container in target["containers"]},
                {name: service["image"] for name, service in services.items()},
            )


if __name__ == "__main__":
    unittest.main()
