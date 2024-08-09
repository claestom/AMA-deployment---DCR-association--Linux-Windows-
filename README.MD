# Azure VM Extension Installer

This script installs the Azure Monitor Agent on an Azure Virtual Machine using the Azure SDK for Python. Supported OS: Linux & Windows.

Once the AMA is being deployed, it will be associated with the specified Data Collection Rule specified in the script. In case the user wants to enable the VM Insights feature on the VM, the ARM template of this DCR is provided in the repo as well under vminsightsdcr.json. This can be deployed to Azure via the custom template deployment in Azure or through PowerShell or Azure CLI.

## Prerequisites

- Python 3.x
- Azure SDK for Python
- Azure credentials (Tenant ID, Client ID, Client Secret)
- Data Collection Rule ID
- Client ID for Azure Monitor Agent

## Installation

1. Clone the repository or download the script.
2. Go to the cloned repository
    ```sh
    cd "AMA-deployment---DCR-association--Linux-Windows-"
    ```
3. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. Set your Azure credentials and other required IDs in the script:
    ```python
    TENANT_ID = "your-tenant-id"
    CLIENT_ID = "your-client-id"
    CLIENT_SECRET = "your-client-secret"
    DATA_COLLECTION_RULE_ID = "your-data-collection-rule-id"
    CLIENT_ID_AMA = "your-client-id-ama"
    ```

2. Run the script to install the VM extension:
    ```sh
    python script.py
    ```

## Code Overview

The script includes the following key components:

- **Imports**: Necessary modules from the Azure SDK and other libraries.
    ```python
    import os
    from azure.identity import ClientSecretCredential
    from azure.mgmt.subscription import SubscriptionClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.monitor.models import DataCollectionRuleAssociationProxyOnlyResource
    from azure.core.exceptions import HttpResponseError
    ```

- **Credentials and IDs**: Variables to store Azure credentials and other required IDs.
    ```python
    TENANT_ID = ""
    CLIENT_ID = ""
    CLIENT_SECRET = ""
    DATA_COLLECTION_RULE_ID = ""
    CLIENT_ID_AMA = ""
    ```

- **Function to Install the AMA**: Function to install the Azure Monitor Agent on an Azure VM.
    ```python
    def install_vm_extension(compute_client, extension_name, vm, vm_name, resource_group):
        extension_parameters = {
            "location": vm.location,
            "publisher": "Microsoft.Azure.Monitor",
            "type": extension_name,
            "type_handler_version": "1.10",
            "auto_upgrade_minor_version": True,
            "settings": {}
        }
        try:
            compute_client.virtual_machine_extensions.begin_create_or_update(
                resource_group_name=resource_group,
                vm_name=vm_name,
                vm_extension_name=extension_name,
                extension_parameters=extension_parameters
            )
        except HttpResponseError as e:
            print(f"An error occurred: {e}")
    ```

## License

This project is licensed under the MIT License.