# Axonius-Panther-Helper

This repository contains a set of custom helpers designed to facilitate integration between Panther SIEM and Axonius (initially announced in [a blog post](https://www.axonius.com/blog/integrating-axonius-asset-inventory-panther-real-time-detections-caasm-siem-enrichment) and presented in [a webinar](https://www.youtube.com/watch?v=HylBky8twWI)). These custom helpers provide a variety of functions for user and device search operations that can be used to leverage the Axonius API.

## Table of Contents

* [Setup & Usage](#setup--usage)
* [Usage Examples](#usage-examples)
* [Available Functions](#available-functions)
    * [find_username](#find_username)
    * [find_hostname](#find_hostname)
    * [find_ip](#find_ip)
    * [find_cloud_id](#find_cloud_id)
    * [user_ip_association](#user_ip_association)
    * [get_hostname_vulnerabilities](#get_hostname_vulnerabilities)
    * [find_cs_aid](#find_cs_aid)

## Setup & Usage
Follow the instructions in the following table to set up and use the Axonius custom helpers in Panther:

1. [Retrieve the API Key and API Secret from Axonius](https://docs.axonius.com/version-4-6/docs/manage-service-accounts#creating-a-service-account). In Role, select Viewer. 

2. Incorporate the Axonius API into AWS Secrets Manager.
Save your Axonius URL, API key, and API secret in AWS Secrets Manager. 
It should look like this:
```json
{
  "url": "https://your-axonius-url.com",
  "api_key": "AXONIUS_API_KEY",
  "api_secret": "AXONIUS_API_SECRET"
}
```

3. Create an AWS role with sufficient permissions to fetch secrets from AWS Secrets Manager.
For example, if the secret was named `Panther/axonius_secrets`:
```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": "secretsmanager:GetSecretValue",
    "Resource": "arn:aws:secretsmanager:Region:AccountId:secret:Panther/axonius_secrets"
  }
}
```
4. Provide the role ARN to Panther support. Panther will provide two ARN roles: one for the detections engine and one for the Python tests engine.

5. Add the ARNs received from Panther to the trust policy within the role you created in AWS.
6. Incorporate AWS secrets helper into Panther. 
Open the AWS secrets helper `custom_aws_secrets_helper.py` and enter relevant values for the following :
    * `AWS_REGION`
    * `AWS_ROLE_ARN`
    * `AWS_ROLE_SESSION_NAME`
7. Add the AWS secrets helper code to your global_helpers folder in Panther.

8. Fetch secrets from AWS
Use the get_secret(SECRET_NAME) function in the AWS secrets helper to fetch secrets from AWS.
9. Test that you are able to fetch secrets from AWS by running a Python test in Panther during the creation of a new detection rule.
10. Add Axonius Helpers to your Panther Environment
Open `custom_axonius_helpers.py` and enter relevant values  for the following:
    * `AX_API_SECRET_NAME`
    * `AX_ADDITIONAL_HEADERS` (this is optional)
11. Add the helper code to the global_helpers folder in your Panther environment.
12. Test that you are able to query Axonius from AWS: Run a Python test in Panther during the creation of a new detection rule.
13. Use Axonius Helper Functions. You can now utilize the functions from `axonius_helpers` within any rule as required.

## Usage Examples
* **Root/Admin user was used:** A user connected via root/admin user to a system. We don’t know which user logged in, but have the public IP. In this case, we can use the `find_ip()` function to find the user based on the public IP address.
* **Sensitive Action:** A user performed a sensitive action or connected to a sensitive resource. In this situation, we can verify if the IP address fits the user in Axonius by using the `find_ip()` or `find_username()` function. This can help us check if that user has used the given public IP before.

* **Data Enrichment:** By adding the output of the `find_username()` or `find_hostname()` functions to the alert context in Panther, we can get more information about the user or device. This can be useful for investigations and incident response.

## Available Functions

Here is a list of the custom helper functions and their descriptions:

### find_username
This function accepts a **user's full name or email address** as input and runs a user query in Axonius. It returns pertinent information about the user, if found.

### find_hostname
This function accepts a **device name** as input and runs a device query in Axonius. It returns valuable information about the device, if located.

### find_ip
This function accepts an **IP address** and runs a query in Axonius. It will return important details about the address, if discovered.

### find_cloud_id
This function accepts a **cloud instance ID** and runs a query in Axonius. It returns critical information about any identified cloud provider machine.

### user_ip_association
This function accepts an **IP address and a username/user email** and executes a query in Axonius. It returns `True` if the user has previously connected with this IP address, and `False` otherwise.

### get_hostname_vulnerabilities
This function accepts a **device name** as input and carries out a device query in Axonius. It returns all vulnerabilities associated with this device.

### find_cs_aid
> **Note**
> This function is only relevant if you are using CrowdStrike and it is connected to your Axonius tenant.

This function takes a **CrowdStrike AID** and runs a query in Axonius. It returns details about this AID, including device name and user, if found.
