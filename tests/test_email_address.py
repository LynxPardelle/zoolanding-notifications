import unittest


class EmailAddressTests(unittest.TestCase):
    def test_accepts_only_the_closed_ascii_mailbox_subset(self):
        from src.common.email_address import is_valid_local_part, is_valid_mailbox

        for value in (
            "operator@example.test",
            "first.last+alerts@example-domain.test",
            "UPPER@example.test",
        ):
            with self.subTest(valid=value):
                self.assertTrue(is_valid_mailbox(value))
        for value in (
            ".a@example.test",
            "a.@example.test",
            "a..b@example.test",
            "display <a@example.test>",
            "a@localhost",
            "a@-example.test",
            "a@example-.test",
            "a@example..test",
            "a\n@example.test",
            "a@exámple.test",
        ):
            with self.subTest(invalid=value):
                self.assertFalse(is_valid_mailbox(value))
        self.assertTrue(is_valid_local_part("billing.ops+alerts"))
        self.assertFalse(is_valid_local_part("billing..ops"))
