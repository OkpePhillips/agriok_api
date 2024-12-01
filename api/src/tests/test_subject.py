import unittest
from certificates import Subject  # Replace 'your_module' with the actual module name


class TestSubject(unittest.TestCase):

    def setUp(self):
        """Set up a Subject instance for testing."""
        self.subject = Subject(
            common_name="Test User",
            country_name="US",
            state_or_province_name="California",
            locality_name="San Francisco",
            organization_name="My Client Org",
        )

    def test_initialization(self):
        """Test that the Subject initializes correctly with provided attributes."""
        self.assertEqual(self.subject["common_name"], "Test User")
        self.assertEqual(self.subject["country_name"], "US")
        self.assertEqual(self.subject["state_or_province_name"], "California")
        self.assertEqual(self.subject["locality_name"], "San Francisco")
        self.assertEqual(self.subject["organization_name"], "My Client Org")

    def test_default_values(self):
        """Test that default values are set correctly."""
        default_subject = Subject(common_name="Default User")
        self.assertEqual(default_subject["country_name"], "")
        self.assertEqual(default_subject["state_or_province_name"], "")
        self.assertEqual(default_subject["locality_name"], "")
        self.assertEqual(default_subject["organization_name"], "")

    def test_subject_attributes(self):
        """Test that all attributes are accessible and correct."""
        self.assertIn("common_name", self.subject)
        self.assertIn("country_name", self.subject)
        self.assertIn("state_or_province_name", self.subject)
        self.assertIn("locality_name", self.subject)
        self.assertIn("organization_name", self.subject)

    def test_missing_common_name(self):
        """Test that initializing without common_name raises a TypeError."""
        with self.assertRaises(TypeError):
            Subject()  # No parameters passed


if __name__ == "__main__":
    unittest.main()
