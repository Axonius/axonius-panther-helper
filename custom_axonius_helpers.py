import requests
from custom_aws_secrets_helper import get_secret

# Axonius Secrets:
AX_API_SECRET_NAME = "<AX_API_SECRET_NAME>"  # Replace <AX_API_SECRET_NAME> with the name of the secret as showed in AWS Secrets Manager
AX_ADDITIONAL_HEADERS = {}  # optional


def build_request():
    """
    Fetches the secret and insert the API to the relevant headers.

    Returns:
        url: the URL stored in the secret for Axonius tenant.
        headers: the required headers for sending the request to Axonius.

    """
    try:
        ax_secrets = get_secret(AX_API_SECRET_NAME)

        url = ax_secrets.get("url")
        headers = {
            "api-key": ax_secrets.get("api_key"),
            "api-secret": ax_secrets.get("api_secret"),
        }
        headers.update(AX_ADDITIONAL_HEADERS)

    except Exception as error:  # pylint: disable=broad-except
        return {"ERROR": f"Failed to retreive secrets {error}"}

    return url, headers


def find_username(username: str) -> dict:
    """
    Gets a username/user email and return details fetched from Axonius.

    Args:
        username: username/user email of the desired user.

    Returns:
        Json with information about the user fetched from Axonius.

    """
    try:
        client = build_request()
        if isinstance(client, dict):
            return {"ERROR": f'Error getting secrets: {client.get("ERROR")}'}
        url = client[0]
        headers = client[1]

        query = f'("specific_data.data.username" == regex("{username}", "i"))'
        fields = [
            "specific_data.data.display_name",
            "specific_data.data.mail",
            "specific_data.data.employee_id",
            "specific_data.data.user_status",
            "specific_data.data.user_manager",
            "specific_data.data.user_title",
            "specific_data.data.user_department",
            "specific_data.data.user_country",
            "specific_data.data.user_telephone_number",
            "specific_data.data.user_created",
            "specific_data.data.last_password_change",
            "specific_data.data.last_logon",
            "specific_data.data.associated_devices",
        ]
        params = {"filter": query, "fields": {"users": fields}}
        try:
            res = requests.get(url=f"{url}/api/users", headers=headers, json=params, timeout=180)
        except requests.exceptions.ConnectionError as error:
            return {"ERROR": f"Error connecting to {url} - {error}"}
        if res.status_code == 200:
            res = res.json()
            if res.get("data"):
                res = res.get("data")[0].get("attributes")
                out = {
                    "user_name": res.get("specific_data.data.display_name"),  # list
                    "user_email": res.get("specific_data.data.mail"),  # list
                    "employee_number": res.get("specific_data.data.employee_id"),  # list
                    "user_status": res.get("specific_data.data.user_status"),  # list
                    "employee_manager": res.get("specific_data.data.user_manager"),  # list
                    "title": res.get("specific_data.data.user_title"),  # list
                    "department": res.get("specific_data.data.user_department"),  # list
                    "location": res.get("specific_data.data.user_country"),  # list
                    "mobilePhone": res.get("specific_data.data.user_telephone_number"),  # list
                    "user_creation_date": res.get("specific_data.data.user_created"),  # list
                    "last_password_change": res.get(
                        "specific_data.data.last_password_change"
                    ),  # str
                    "last_logon": res.get("specific_data.data.last_logon"),  # str
                    "associated_devices": res.get("specific_data.data.associated_devices"),  # list
                }
                return out
            return {"ERROR": f"{username} was not found."}
        return {"ERROR": f"{url}/api/users response is {res.status_code} {res.content}"}
    except Exception as error:  # pylint: disable=broad-except
        return {"ERROR": str(error)}


def find_hostname(hostname: str) -> dict:
    """
    Gets a device name and return details fetched from Axonius.

    Args:
        hostname: name of the desired device.

    Returns:
        Json with information about the device fetched from Axonius.

    """
    try:
        client = build_request()
        if isinstance(client, dict):
            return {"ERROR": f'Error getting secrets: {client.get("ERROR")}'}
        url = client[0]
        headers = client[1]

        query = f'("specific_data.data.name" == "{hostname}")'
        fields = [
            "specific_data.data.os.type_distribution_preferred",
            "specific_data.data.serial_number_preferred",
            "specific_data.data.last_seen",
            "specific_data.data.public_ips",
            "specific_data.data.users",
            "specific_data.data.last_used_users_mail_association",
        ]
        params = {"filter": query, "fields": {"devices": fields}}
        try:
            res = requests.get(url=f"{url}/api/devices", headers=headers, json=params, timeout=180)
        except requests.exceptions.ConnectionError as error:
            return {"ERROR": f"Error connecting to {url} - {error}"}
        if res.status_code == 200:
            res = res.json()
            if res.get("data"):
                res = res.get("data")[0].get("attributes")
                out = {
                    "device_name": hostname,  # str
                    "os": res.get("specific_data.data.os.type_distribution_preferred"),  # str
                    "serial_number": res.get("specific_data.data.serial_number_preferred"),  # str
                    "last_seen": res.get("specific_data.data.last_seen"),  # str
                    "public_ips": res.get("specific_data.data.public_ips")
                    if res.get("specific_data.data.public_ips")
                    else res.get("specific_data.data.network_interfaces.ips"),  # list
                    "users": res.get("specific_data.data.users")
                    if res.get("specific_data.data.users")
                    else res.get("specific_data.data.last_used_users_mail_association"),  # list
                }
                return out
            return {"ERROR": f"{hostname} was not found."}
        return {"ERROR": f"{url}/api/devices response is {res.status_code} {res.content}"}
    except Exception as error:  # pylint: disable=broad-except
        return {"ERROR": str(error)}


def find_ip(ip_address: str) -> dict:  # pylint: disable=R1260,R0911
    """
    Gets an IP address and return details fetched from Axonius.

    Args:
        ip_address: The desired IP address.

    Returns:
        Json with information about the IP address fetched from Axonius.

    """
    try:
        client = build_request()
        if isinstance(client, dict):
            return {"ERROR": f'Error getting secrets: {client.get("ERROR")}'}
        url = client[0]
        headers = client[1]

        query = f'("specific_data.data.last_known_ips" == regex("{ip_address}", "i"))'
        fields = [
            "specific_data.data.username",
            "specific_data.data.last_seen",
        ]
        params = {"filter": query, "fields": {"users": fields}}
        try:
            res = requests.get(url=f"{url}/api/users", headers=headers, json=params, timeout=180)
        except requests.exceptions.ConnectionError as error:
            return {"ERROR": f"Error connecting to {url} - {error}"}
        if res.status_code == 200:
            res = res.json()
            if res.get("data"):
                res = res.get("data")
                ip_users = []
                for record in res:
                    ip_users.append(record.get("attributes").get("specific_data.data.username"))

                res = res[0].get("attributes")
                out = {
                    "ip_address": ip_address,
                    "office_ip_address": len(ip_users) >= 10,
                    "last_seen": res.get("specific_data.data.last_seen"),
                    "users_count": len(ip_users),
                    "users": ip_users,
                }
                return out

        query = f'("specific_data.data.network_interfaces.ips" == regex("{ip_address}", "i"))'
        fields = [
            "specific_data.data.last_seen",
            "specific_data.data.email",
        ]
        params = {"filter": query, "fields": {"devices": fields}}
        try:
            res = requests.get(url=f"{url}/api/devices", headers=headers, json=params, timeout=180)
        except requests.exceptions.ConnectionError as error:
            return {"ERROR": f"Error connecting to {url} - {error}"}
        if res.status_code == 200:
            res = res.json()
            if res.get("data"):
                res = res.get("data")
                ip_users = []
                for record in res:
                    ip_users.append(record.get("attributes").get("specific_data.data.email"))

                res = res[0].get("attributes")
                out = {
                    "ip_address": ip_address,
                    "office_ip_address": len(ip_users) >= 10,
                    "last_seen:": res.get("specific_data.data.last_seen"),
                    "users_count": len(ip_users),
                    "users": ip_users,
                }
                return out

            return {"ERROR": f"{ip_address} was not found."}
        return {"ERROR": f"{url}/api/users response is {res.status_code} {res.content}"}
    except Exception as error:  # pylint: disable=broad-except
        return {"ERROR": str(error)}


def find_cloud_id(cloud_id: str) -> dict:
    """
    Gets a cloud ID and return details fetched from Axonius.

    Args:
        cloud_id: The ID of the desired cloud instance.

    Returns:
        Json with information about the cloud instance address fetched from Axonius.

    """
    try:
        client = build_request()
        if isinstance(client, dict):
            return {"ERROR": f'Error getting secrets: {client.get("ERROR")}'}
        url = client[0]
        headers = client[1]

        query = f'("specific_data.data.cloud_id" == "{cloud_id}")'
        fields = [
            "specific_data.data.name",
            "specific_data.data.cloud_id.cloud_id",
            "specific_data.data.cloud_provider_account_id",
            "specific_data.data.cloud_provider_account_name",
            "specific_data.data.network_interfaces.ips",
            "specific_data.data.os.type_distribution_preferred",
            "specific_data.data.last_seen",
            "specific_data.data.power_state",
        ]
        params = {"filter": query, "fields": {"devices": fields}}
        try:
            res = requests.get(url=f"{url}/api/devices", headers=headers, json=params, timeout=180)
        except requests.exceptions.ConnectionError as error:
            return {"ERROR": f"Error connecting to {url} - {error}"}
        if res.status_code == 200:
            res = res.json()
            if res.get("data"):
                res = res.get("data")[0].get("attributes")
                out = {
                    "cloud_id": cloud_id,
                    "instance_name": res.get("specific_data.data.name"),
                    "account_id": res.get("specific_data.data.cloud_provider_account_id"),
                    "account_name": res.get("specific_data.data.cloud_provider_account_name"),
                    "ip_addresses": res.get("specific_data.data.network_interfaces.ips"),
                    "os": res.get("specific_data.data.os.type_distribution_preferred"),
                    "last_seen": res.get("specific_data.data.last_seen"),
                    "status": res.get("specific_data.data.power_state"),
                }
                return out
            return {"ERROR": f"{cloud_id} was not found"}
        return {"ERROR": f"{url}/api/devices response is {res.status_code} {res.content}"}
    except Exception as error:  # pylint: disable=broad-except
        return {"ERROR": str(error)}


def user_ip_association(ip_address: str, username: str) -> bool:
    """
    Checks if a given user is related to a given IP address.

    Args:
        ip_address: An IP address of a user.
        username: A username/user email.

    Returns:
        True of this IP address is related to the user else it returns False.
    """
    ax_ip = find_ip(ip_address)
    if not ax_ip.get("ERROR") and (
        username in (item for sublist in ax_ip.get("users") for item in sublist)
        or username in ax_ip.get("users")
    ):
        return True
    return False


def get_hostname_vulnerabilities(hostname: str) -> dict:
    """
    Gets a device name and return all existing vulnerabilities on this device fetched from Axonius.

    Args:
        hostname: name of the desired device.

    Returns:
        Json with information about the device's vulnerabilities fetched from Axonius.

    """
    try:
        client = build_request()
        if isinstance(client, dict):
            return {"ERROR": f'Error getting secrets: {client.get("ERROR")}'}
        url = client[0]
        headers = client[1]

        query = f'("specific_data.data.name" == "{hostname}")'
        fields = [
            "specific_data.data.cisa_vulnerabilities",
            "specific_data.data.software_cves",
        ]
        params = {"filter": query, "fields": {"devices": fields}}
        try:
            res = requests.get(url=f"{url}/api/devices", headers=headers, json=params, timeout=180)
        except requests.exceptions.ConnectionError as error:
            return {"ERROR": f"Error connecting to {url} - {error}"}
        if res.status_code == 200:
            res = res.json()
            if res.get("data"):
                res = res.get("data")[0].get("attributes")
                out = {
                    "cisa_vulnerabilities": res.get(
                        "specific_data.data.cisa_vulnerabilities"
                    ),  # list
                    "software_vulnerabilities": res.get("specific_data.data.software_cves"),  # list
                }
                return out
            return {"ERROR": f"{hostname} was not found."}
        return {"ERROR": f"{url}/api/devices response is {res.status_code} {res.content}"}
    except Exception as error:  # pylint: disable=broad-except
        return {"ERROR": str(error)}


def find_cs_aid(aid: str) -> dict:
    """
    Translate Crowdstrike AID to a device name.

    Args:
        aid: Crowdstrike AID of the desired device.

    Returns:
        Json with details about the device found based on the provided CS AID.
    """
    try:
        client = build_request()
        if isinstance(client, dict):
            return {"ERROR": f'Error getting secrets: {client.get("ERROR")}'}
        url = client[0]
        headers = client[1]

        query = f'("adapters_data.crowd_strike_adapter.device_id" == "{aid}")'
        fields = [
            "specific_data.data.os.type_distribution_preferred",
            "specific_data.data.serial_number_preferred",
            "specific_data.data.last_seen",
            "specific_data.data.public_ips",
            "specific_data.data.users",
            "specific_data.data.last_used_users_mail_association",
            "adapters_data.crowd_strike_adapter.external_ip",
            "adapters_data.crowd_strike_adapter.hostname",
        ]
        params = {"filter": query, "fields": {"devices": fields}}
        try:
            res = requests.get(url=f"{url}/api/devices", headers=headers, json=params, timeout=180)
            if res.status_code == 200:
                res = res.json()
                if res.get("data"):
                    res = res.get("data")[0].get("attributes")
                    out = {
                        "hostname": res.get("adapters_data.crowd_strike_adapter.hostname"),
                        "cs_device_aid": aid,  # str
                        "os": res.get("specific_data.data.os.type_distribution_preferred"),  # str
                        "serial_number": res.get(
                            "specific_data.data.serial_number_preferred"
                        ),  # str
                        "last_seen": res.get("specific_data.data.last_seen"),  # str
                        "external_ip": res.get("adapters_data.crowd_strike_adapter.external_ip"),
                        "users": res.get("specific_data.data.users")
                        if res.get("specific_data.data.users")
                        else res.get("specific_data.data.last_used_users_mail_association"),  # list
                    }
                    return out
                return {"ERROR": f"{aid} was not found"}
            return {"ERROR": f"{url}/api/devices response is {res.status_code} {res.content}"}
        except requests.exceptions.ConnectionError as error:
            return {"ERROR": f"Error connecting to {url} - {error}"}
    except Exception as error:  # pylint: disable=broad-except
        return {"ERROR": str(error)}
