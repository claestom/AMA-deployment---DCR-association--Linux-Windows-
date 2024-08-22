# Automate the observability of your VMs using Python

This script installs the Azure Monitor Agent on an Azure Virtual Machine using the Azure SDK for Python. Supported OS: Linux & Windows.

Once the AMA is being deployed, it will be associated with the specified Data Collection Rule specified in the script. In case the user wants to enable the VM Insights feature on the VM, the ARM template of this DCR is provided in the repo as well under vminsightsdcr.json. This can be deployed to Azure via the custom template deployment in Azure or through PowerShell or Azure CLI.

## Resources

* [Azure Monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/)
* [Azure Monitor Agent: introduction](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-overview)
* [Data collection rule: introduction](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-data-collection)

## Prerequisites

- Python 3.x
- Azure SDK for Python
- Azure credentials (Tenant ID, Client ID, Client Secret). [Tutorial on how to create this.](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=client-secret). Note: store the ClientSecret somewhere as it will not be displayed again after creation.
- Data Collection Rule ID (below more information on how to create this)

**Note**: Ensure that your Linux or Windows OS version is supported by the Azure Monitor Agent. You can check the full list [here](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-supported-operating-systems).

### If your VM is running on-premises or in a different cloud provider, you need to first Arc enable the VM:

In order to install the Azure Monitor Agent on Virtual Machines outside of Azure, it is required to onboard these VMs using the Azure Arc Agent. Using [following link](https://learn.microsoft.com/en-us/azure/azure-arc/servers/deployment-options), you will find multiple onboarding options: Group Policy, PowerShell, SCVMM, Service Principal...

### Data Collection rule

Data collection rules (DCRs) are stored in Azure so they can be centrally deployed and managed like any other Azure resource. They're sets of instructions supporting data collection using the Azure Monitor pipeline. More information [here](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-overview).

* If you would like to enable VM Insights on the VM, you can leverage the [DCR ARM template](vminsightsdcr.json). 

    More information how to deploy this template can be found [here](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/quickstart-create-templates-use-the-portal). Note: in the third step of the tutorial, select "Build your own template in the editor". Copy paste the content from this [DCR ARM template](vminsightsdcr.json) into the editor. Next, click "save" and follow the next steps.

* If you want to only select a defined type of metrics and/or logs, you can customize your DCR by creating them yourself. How to do this is explained [here](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-create-edit?tabs=portal), with tools like the Portal, Az CLI, PS, APIs or ARM.

Once the DCR is being created, go to the DCR instance in the Portal and retrieve the Resource ID. You can find this ID if you go to JSON VIEW if you are in the DCR in the Portal (see red rectangle).

![alt text](imgs/DCR%20resource%20ID.png)

## Installation of environment

1. Clone the repository or download the script ([how does this work?](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository))
2. Go to the cloned repository
    ```sh
    cd "AMA-deployment---DCR-association--Linux-Windows-"
    ```
3. Create a new virtual environment
    ```sh
    python -m venv .
    ```
4. Activate the new virtual environment
    
    *Powershell*
    ```sh
    .venv\Scripts\Activate.ps1 or Scripts\Activate.ps1
    ```
    *Command Prompt Windows*
    ```sh
    .venv\Scripts\activate.bat or Scripts\activate.bat
    ```
    *Mac/Linux*
    ```sh
    .venv/bin/activate or bin/activate
    ```
5. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

## Local usage to test

1. Enter the *local-script* folder
    ```sh
    cd "local-script"
    ```
2. Open Visual Studio
    ```sh
    code .
    ```
3. Create a new file called ".env" in the folder
4. Add to the .env file your Azure credentials and other required IDs in the script:
    ```python
    TENANT_ID=your-tenant-id
    CLIENT_ID=your-client-id
    CLIENT_SECRET=your-client-secret
    DATA_COLLECTION_RULE_ID=your-data-collection-rule-id
    ```

5. Run the script to install the VM extension:
    ```sh
    python script.py
    ```

## Integration with Azure Functions

TO BE ADDED SOON

## Code Overview

### `script.py`

This is the main script that installs the VM extension and associates a Data Collection Rule with the VM. It includes the following key components:

#### Function: `install_vm_extension`

This function installs a the Azure Monitor Agent as a VM extension on an Azure VM.

- **Parameters**:
    - `compute_client`: The ComputeManagementClient instance.
    - `extension_name`: The name of the extension to install.
    - `vm`: The VM object.
    - `vm_name`: The name of the VM.
    - `resource_group`: The resource group of the VM.

- **Implementation**:
    ```python
    try:
        compute_client.virtual_machine_extensions.begin_create_or_update(
            resource_group_name=resource_group,
            vm_name=vm_name,
            vm_extension_name=extension_name,
            extension_parameters=extension_parameters
        ).result()
        print(f"{extension_name} installed on VM {vm_name}.")
    except HttpResponseError as e:
        print(f"Failed to install {extension_name} on VM {vm_name}. Error: {e}")
    ```

- **Review**:
    - The function attempts to install the VM extension and waits for the operation to complete using `.result()`.
    - It handles `HttpResponseError` exceptions and prints an error message if the installation fails.

#### Function: `associate_data_collection_rule`

This function associates a Data Collection Rule with an Azure VM.

- **Parameters**:
    - `monitor_client`: The MonitorManagementClient instance.
    - `vm`: The VM object.
    - `vm_name`: The name of the VM.

- **Implementation**:
    ```python
    association_parameters = DataCollectionRuleAssociationProxyOnlyResource(
        data_collection_rule_id=DATA_COLLECTION_RULE_ID,
        description="Data Collection Rule Association"
    )
    try:
        monitor_client.data_collection_rule_associations.create(
            resource_uri=vm.id,
            association_name=vm_name,
            body=association_parameters
        )
        print(f"VM {vm_name} associated with Data Collection Rule.")
    except HttpResponseError as e:
        print(f"Failed to associate VM {vm_name} with Data Collection Rule. Error: {e}")
    ```

- **Review**:
    - The function creates an association between the VM and the Data Collection Rule.
    - It handles `HttpResponseError` exceptions and prints an error message if the association fails.

#### Function: `process_vm`

This function processes a VM to check its status and perform actions based on its state.

- **Parameters**:
    - `vm`: The VM object.
    - `compute_client`: The ComputeManagementClient instance.
    - `monitor_client`: The MonitorManagementClient instance.
    - `subscription_id`: The subscription ID.

- **Implementation**:
    ```python
    vm_name = vm.name
    resource_group = vm.id.split("/")[4]
    instance_view = compute_client.virtual_machines.instance_view(resource_group, vm_name)
    
    is_running = any(status.code == 'PowerState/running' for status in instance_view.statuses)
    
    if not is_running:
        print(f"VM {vm_name} is not running. Skipping.")
    ```

- **Review**:
    - The function retrieves the VM's instance view to check its power state.
    - It skips further processing if the VM is not running