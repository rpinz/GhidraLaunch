import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/release.yml"


class ReleaseWorkflowTests(unittest.TestCase):
    def test_publish_commands_have_explicit_repository_without_checkout(self):
        workflow = WORKFLOW.read_text()
        publish = workflow.split("\n  publish:\n", 1)[1]
        step = publish.split("      - name: Publish GitHub release\n", 1)[1]
        step = step.split("\n      - ", 1)[0]
        environment = step.split("        env:\n", 1)[1].split("        run:", 1)[0]
        self.assertIn("          GH_REPO: ${{ github.repository }}\n", environment)


if __name__ == "__main__":
    unittest.main()
