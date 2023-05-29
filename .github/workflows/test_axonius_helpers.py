import unittest
from unittest.mock import patch, MagicMock
from requests.exceptions import ConnectionError
import sys

sys.path.append("../..")
from custom_axonius_helpers import (
    find_username,
    find_hostname,
    find_ip,
    find_cloud_id,
    user_ip_association,
    get_hostname_vulnerabilities,
    find_cs_aid,
)


class ScriptTestCase(unittest.TestCase):
    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_find_username_success(self, mock_get, mock_get_secret):
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "attributes": {
                        "specific_data.data.display_name": "John Doe",
                        "specific_data.data.mail": "john.doe@example.com",
                        "specific_data.data.employee_id": "123",
                        "specific_data.data.user_status": "Active",
                        "specific_data.data.user_manager": "Some Manager",
                        "specific_data.data.user_title": "Sales Engineer",
                        "specific_data.data.user_department": "Sales",
                        "specific_data.data.user_country": "US",
                        "specific_data.data.user_telephone_number": "+123456",
                        "specific_data.data.user_created": "1.1.23",
                        "specific_data.data.last_password_change": "2.1.23",
                        "specific_data.data.last_logon": "3.1.23",
                        "specific_data.data.associated_devices": ["pc1", "pc2"],
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        result = find_username("john.doe")

        # Assertions
        self.assertEqual(result["user_name"], "John Doe")
        self.assertEqual(result["user_email"], "john.doe@example.com")
        self.assertEqual(result["employee_number"], "123")
        self.assertEqual(result["user_status"], "Active")
        self.assertEqual(result["employee_manager"], "Some Manager")
        self.assertEqual(result["title"], "Sales Engineer")
        self.assertEqual(result["department"], "Sales")
        self.assertEqual(result["location"], "US")
        self.assertEqual(result["mobilePhone"], "+123456")
        self.assertEqual(result["user_creation_date"], "1.1.23")
        self.assertEqual(result["last_password_change"], "2.1.23")
        self.assertEqual(result["last_logon"], "3.1.23")
        self.assertEqual(result["associated_devices"], ["pc1", "pc2"])

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_find_username_error(self, mock_get, mock_get_secret):
        # Mock the response from get_secret
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        # Mock the ConnectionError from requests.get
        mock_get.side_effect = ConnectionError("Connection error")

        # Call the function to test
        result = find_username("john.doe")

        # Assertions
        self.assertEqual(
            result["ERROR"], "Error connecting to https://example.com - Connection error"
        )

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_find_hostname_success(self, mock_get, mock_get_secret):
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "attributes": {
                        "specific_data.data.os.type_distribution_preferred": "Linux",
                        "specific_data.data.serial_number_preferred": "12345",
                        "specific_data.data.last_seen": "3.1.23",
                        "specific_data.data.public_ips": ["1.1.1.1"],
                        "specific_data.data.users": ["John Doe"],
                        "specific_data.data.last_used_users_mail_association": [
                            "John.Doe@example.com"
                        ],
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        result = find_hostname("server1")

        # Assertions
        self.assertEqual(result["device_name"], "server1")
        self.assertEqual(result["os"], "Linux")
        self.assertEqual(result["serial_number"], "12345")
        self.assertEqual(result["last_seen"], "3.1.23")
        self.assertEqual(result["public_ips"], ["1.1.1.1"])
        self.assertEqual(result["users"], ["John Doe"])

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_find_hostname_error(self, mock_get, mock_get_secret):
        # Mock the response from get_secret
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        # Mock the ConnectionError from requests.get
        mock_get.side_effect = ConnectionError("Connection error")

        # Call the function to test
        result = find_hostname("server1")

        # Assertions
        self.assertEqual(
            result["ERROR"], "Error connecting to https://example.com - Connection error"
        )

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_find_ip_success(self, mock_get, mock_get_secret):
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "attributes": {
                        "specific_data.data.username": "user_1",
                        "specific_data.data.last_seen": "2.1.23",
                    }
                },
                {
                    "attributes": {
                        "specific_data.data.username": "user_2",
                        "specific_data.data.last_seen": "1.1.23",
                    }
                },
            ]
        }
        mock_get.return_value = mock_response

        result = find_ip("1.1.1.1")

        # Assertions
        self.assertEqual(result["ip_address"], "1.1.1.1")
        self.assertEqual(result["office_ip_address"], False)
        self.assertEqual(result["last_seen"], "2.1.23")
        self.assertEqual(result["users_count"], 2)
        self.assertEqual(result["users"], ["user_1", "user_2"])

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_find_ip_error(self, mock_get, mock_get_secret):
        # Mock the response from get_secret
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        # Mock the ConnectionError from requests.get
        mock_get.side_effect = ConnectionError("Connection error")

        # Call the function to test
        result = find_ip("1.1.1.1")

        # Assertions
        self.assertEqual(
            result["ERROR"], "Error connecting to https://example.com - Connection error"
        )

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_find_cloud_id_success(self, mock_get, mock_get_secret):
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "attributes": {
                        "specific_data.data.name": "linux_server_1",
                        "specific_data.data.cloud_id.cloud_id": "i-12312312123123312",
                        "specific_data.data.cloud_provider_account_id": "123123123123",
                        "specific_data.data.cloud_provider_account_name": "servers_dev",
                        "specific_data.data.network_interfaces.ips": ["1.1.1.1", "2.2.2.2"],
                        "specific_data.data.os.type_distribution_preferred": "Linux Ubuntu 22.04",
                        "specific_data.data.last_seen": "2.1.23",
                        "specific_data.data.power_state": ["TurnedOn"],
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        result = find_cloud_id("i-12312312123123312")

        # Assertions
        self.assertEqual(result["cloud_id"], "i-12312312123123312")
        self.assertEqual(result["instance_name"], "linux_server_1")
        self.assertEqual(result["account_id"], "123123123123")
        self.assertEqual(result["account_name"], "servers_dev")
        self.assertEqual(result["ip_addresses"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(result["os"], "Linux Ubuntu 22.04")
        self.assertEqual(result["last_seen"], "2.1.23")
        self.assertEqual(result["status"], ["TurnedOn"])

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_find_cloud_id_error(self, mock_get, mock_get_secret):
        # Mock the response from get_secret
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        # Mock the ConnectionError from requests.get
        mock_get.side_effect = ConnectionError("Connection error")

        # Call the function to test
        result = find_cloud_id("i-12312312123123312")

        # Assertions
        self.assertEqual(
            result["ERROR"], "Error connecting to https://example.com - Connection error"
        )

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_user_ip_association_success(self, mock_get, mock_find_ip):
        # Mock the response from find_ip
        mock_find_ip = MagicMock(
            return_value={
                "ip_address": "1.1.1.1",
                "office_ip_address": False,
                "last_seen": "2.1.23",
                "users_count": 2,
                "users": ["user_1", "user_2"],
            }
        )
        with patch("custom_axonius_helpers.find_ip", mock_find_ip):
            # Call the function to test
            result = user_ip_association("1.1.1.1", "user_1")

            # Assertions
            self.assertEqual(result, True)

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_get_hostname_vulnerabilities_success(self, mock_get, mock_get_secret):
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "attributes": {
                        "specific_data.data.cisa_vulnerabilities": [
                            {
                                "action": "Apply updates per vendor instructions.",
                                "added": "Mon, 22 May 2023 00:00:00 GMT",
                                "cve_id": "CVE-2023-28204",
                                "desc": "Apple iOS, iPadOS, macOS, tvOS, watchOS, and Safari WebKit contain an out-of-bounds read vulnerability that may disclose sensitive information.",
                                "due_date": "Mon, 12 Jun 2023 00:00:00 GMT",
                                "notes": "https://support.apple.com/HT213757, https://support.apple.com/HT213758, https://support.apple.com/HT213761, https://support.apple.com/HT213762, https://support.apple.com/HT213764, https://support.apple.com/HT213765",
                                "product": "Multiple Products",
                                "vendor": "Apple",
                                "vulnerability_name": "Apple Multiple Products WebKit Out-of-Bounds Read Vulnerability",
                            },
                            {
                                "action": "Apply updates per vendor instructions.",
                                "added": "Mon, 22 May 2023 00:00:00 GMT",
                                "cve_id": "CVE-2023-32373",
                                "desc": "Apple iOS, iPadOS, macOS, tvOS, watchOS, and Safari WebKit contain a use-after-free vulnerability that leads to code execution.",
                                "due_date": "Mon, 12 Jun 2023 00:00:00 GMT",
                                "notes": "https://support.apple.com/HT213757, https://support.apple.com/HT213758, https://support.apple.com/HT213761, https://support.apple.com/HT213762, https://support.apple.com/HT213764, https://support.apple.com/HT213765",
                                "product": "Multiple Products",
                                "vendor": "Apple",
                                "vulnerability_name": "Apple Multiple Products WebKit Use-After-Free Vulnerability",
                            },
                        ],
                        "specific_data.data.software_cves": [
                            {"cve_id": "CVE-2023-32409"},
                            {
                                "cve_id": "CVE-2023-32409",
                                "cve_severity": "CRITICAL",
                                "cve_synopsis": "Actively used",
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
                                "exploitability_score": 2.8,
                                "software_name": "Mac OS 13",
                                "status": "open",
                            },
                        ],
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        result = get_hostname_vulnerabilities("server1")

        # Assertions
        self.assertEqual(
            result["cisa_vulnerabilities"],
            [
                {
                    "action": "Apply updates per vendor instructions.",
                    "added": "Mon, 22 May 2023 00:00:00 GMT",
                    "cve_id": "CVE-2023-28204",
                    "desc": "Apple iOS, iPadOS, macOS, tvOS, watchOS, and Safari WebKit contain an out-of-bounds read vulnerability that may disclose sensitive information.",
                    "due_date": "Mon, 12 Jun 2023 00:00:00 GMT",
                    "notes": "https://support.apple.com/HT213757, https://support.apple.com/HT213758, https://support.apple.com/HT213761, https://support.apple.com/HT213762, https://support.apple.com/HT213764, https://support.apple.com/HT213765",
                    "product": "Multiple Products",
                    "vendor": "Apple",
                    "vulnerability_name": "Apple Multiple Products WebKit Out-of-Bounds Read Vulnerability",
                },
                {
                    "action": "Apply updates per vendor instructions.",
                    "added": "Mon, 22 May 2023 00:00:00 GMT",
                    "cve_id": "CVE-2023-32373",
                    "desc": "Apple iOS, iPadOS, macOS, tvOS, watchOS, and Safari WebKit contain a use-after-free vulnerability that leads to code execution.",
                    "due_date": "Mon, 12 Jun 2023 00:00:00 GMT",
                    "notes": "https://support.apple.com/HT213757, https://support.apple.com/HT213758, https://support.apple.com/HT213761, https://support.apple.com/HT213762, https://support.apple.com/HT213764, https://support.apple.com/HT213765",
                    "product": "Multiple Products",
                    "vendor": "Apple",
                    "vulnerability_name": "Apple Multiple Products WebKit Use-After-Free Vulnerability",
                },
            ],
        )
        self.assertEqual(
            result["software_vulnerabilities"],
            [
                {"cve_id": "CVE-2023-32409"},
                {
                    "cve_id": "CVE-2023-32409",
                    "cve_severity": "CRITICAL",
                    "cve_synopsis": "Actively used",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
                    "exploitability_score": 2.8,
                    "software_name": "Mac OS 13",
                    "status": "open",
                },
            ],
        )

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_get_hostname_vulnerabilities_error(self, mock_get, mock_get_secret):
        # Mock the response from get_secret
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        # Mock the ConnectionError from requests.get
        mock_get.side_effect = ConnectionError("Connection error")

        # Call the function to test
        result = get_hostname_vulnerabilities("server1")

        # Assertions
        self.assertEqual(
            result["ERROR"], "Error connecting to https://example.com - Connection error"
        )

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_find_cs_aid_success(self, mock_get, mock_get_secret):
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "attributes": {
                        "specific_data.data.os.type_distribution_preferred": "Linux",
                        "specific_data.data.serial_number_preferred": "12345",
                        "specific_data.data.last_seen": "3.1.23",
                        "specific_data.data.public_ips": ["1.1.1.1"],
                        "specific_data.data.users": ["John Doe"],
                        "specific_data.data.last_used_users_mail_association": [
                            "John.Doe@example.com"
                        ],
                        "adapters_data.crowd_strike_adapter.external_ip": "1.1.1.1",
                        "adapters_data.crowd_strike_adapter.hostname": "server1",
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        result = find_cs_aid("64659c3b12394cbcb9ca7231e435d123")

        # Assertions
        self.assertEqual(result["hostname"], "server1")
        self.assertEqual(result["cs_device_aid"], "64659c3b12394cbcb9ca7231e435d123")
        self.assertEqual(result["os"], "Linux")
        self.assertEqual(result["serial_number"], "12345")
        self.assertEqual(result["last_seen"], "3.1.23")
        self.assertEqual(result["external_ip"], "1.1.1.1")
        self.assertEqual(result["users"], ["John Doe"])

    @patch("custom_axonius_helpers.get_secret")
    @patch("custom_axonius_helpers.requests.get")
    def test_find_cs_aid_error(self, mock_get, mock_get_secret):
        # Mock the response from get_secret
        mock_get_secret.return_value = {
            "url": "https://example.com",
            "api_key": "api_key",
            "api_secret": "api_secret",
        }

        # Mock the ConnectionError from requests.get
        mock_get.side_effect = ConnectionError("Connection error")

        # Call the function to test
        result = find_cs_aid("64659c3b12394cbcb9ca7231e435d123")

        # Assertions
        self.assertEqual(
            result["ERROR"], "Error connecting to https://example.com - Connection error"
        )


if __name__ == "__main__":
    unittest.main()
