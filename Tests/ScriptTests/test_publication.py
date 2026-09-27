import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_publication.py"
SPEC = importlib.util.spec_from_file_location("check_publication", SCRIPT)
publication = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publication)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git("init", "--quiet")
        root_patch = patch.object(publication, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.root), *args], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout

    def stage(self, name, data):
        (self.root / name).write_bytes(data)
        self.git("add", "--", name)

    def inspect(self):
        return publication.inspect_sources(publication.source_files())

    def test_batch_handles_empty_duplicate_binary_and_newline_named_blobs(self):
        for name, data in [("empty.txt", b""), ("first.txt", b"same\n"),
                           ("second.txt", b"same\n"), ("with\nnewline.bin", b"\x00\xff\n")]:
            self.stage(name, data)
        errors, checked = self.inspect()
        self.assertEqual(errors, [])
        self.assertEqual(len(checked), 4)
        self.assertEqual(checked["with\nnewline.bin"][0], b"\x00\xff\n")

    def test_staged_bytes_are_checked_even_when_working_copy_is_clean(self):
        self.stage("source.txt", b"test-blocked-content")
        (self.root / "source.txt").write_bytes(b"clean")
        with patch.object(publication, "PATTERNS", {"test sentinel": b"test-blocked-content"}):
            errors, _ = self.inspect()
        self.assertEqual(errors, [("source.txt", "Git index: test sentinel")])

    def test_working_bytes_are_checked_even_when_index_is_clean(self):
        self.stage("source.txt", b"clean")
        (self.root / "source.txt").write_bytes(b"test-blocked-content")
        with patch.object(publication, "PATTERNS", {"test sentinel": b"test-blocked-content"}):
            errors, _ = self.inspect()
        self.assertEqual(errors, [("source.txt", "working tree: test sentinel")])

    def test_oversized_index_blob_is_rejected_before_content_is_requested(self):
        self.stage("large.txt", b"x" * (5 * 1024 * 1024 + 1))
        (self.root / "large.txt").write_bytes(b"small working copy")
        with patch.object(publication, "inspect_index_contents", wraps=publication.inspect_index_contents) as reader:
            errors, checked = self.inspect()
        self.assertEqual(errors, [("large.txt", "Git index entry exceeds 5 MiB")])
        self.assertEqual(checked, {})
        self.assertEqual(reader.call_args.args[0], [])

    def test_ignored_untracked_files_are_excluded_and_tracked_ignored_files_fail(self):
        self.stage(".gitignore", b"private.txt\n")
        (self.root / "private.txt").write_bytes(b"private test data")
        errors, checked = self.inspect()
        self.assertEqual(errors, [])
        self.assertNotIn("private.txt", checked)
        self.git("add", "--force", "private.txt")
        errors, checked = self.inspect()
        self.assertEqual(errors, [("private.txt", "tracked file is excluded by publication ignore rules")])
        self.assertNotIn("private.txt", checked)

    def test_tracked_deletion_still_checks_staged_bytes(self):
        self.stage("deleted.txt", b"test-blocked-content")
        (self.root / "deleted.txt").unlink()
        with patch.object(publication, "PATTERNS", {"test sentinel": b"test-blocked-content"}):
            errors, checked = self.inspect()
        self.assertEqual(errors, [("deleted.txt", "Git index: test sentinel")])
        self.assertEqual(checked, {})

    def test_untracked_only_repository_needs_no_index_objects(self):
        (self.root / "new.txt").write_bytes(b"new source")
        errors, checked = self.inspect()
        self.assertEqual(errors, [])
        self.assertEqual(checked["new.txt"][0], b"new source")


if __name__ == "__main__":
    unittest.main()
