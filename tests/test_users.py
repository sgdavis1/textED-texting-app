import builtins
import unittest
from parental_bot.users import get_user_by_phone, get_random_memory_by_user


class TestUsers(unittest.TestCase):
    def test_get_user_by_phone_1(self):
        mock_phone = "+12174191354"
        user = get_user_by_phone(mock_phone)
        self.assertEqual(user.get("name"), "Cindy Johnson")

    def test_get_user_by_phone_2(self):
        mock_phone = "not a phone number"
        with self.assertRaises(KeyError):
            user = get_user_by_phone(mock_phone)

    def test_get_random_memory_by_user_1(self):
        mock_user = {"memories": ["Greg eats Jed's face"]}
        ret_value = get_random_memory_by_user(mock_user)
        self.assertEqual(ret_value, "Greg eats Jed's face")

    def test_get_random_memory_by_user_2(self):
        mock_user = {"memories": []}
        with self.assertRaises(IndexError):
            ret_value = get_random_memory_by_user(mock_user)
