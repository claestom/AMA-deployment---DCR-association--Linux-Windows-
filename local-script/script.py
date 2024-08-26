import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import DataCollectionRuleAssociationProxyOnlyResource
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError
from azure.mgmt.compute.models import VirtualMachineIdentity, ResourceIdentityType

load_dotenv()

# Retrieve the credentials from environment variables
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DATA_COLLECTION_RULE_ID = os.getenv("DATA_COLLECTION_RULE_ID")

# Tag key/value pairs

VM_TAG = ["amainstall", "true"]
SUBSCRIPTION_TAG = ["amainstall", "true"]

def enable_system_assigned_identity(resource_group_name, vm_name, subscription_id, credential):
    compute_client = ComputeManagementClient(credential, subscription_id)
    vm = compute_client.virtual_machines.get(resource_group_name, vm_name)

    if vm.identity and vm.identity.type == ResourceIdentityType.system_assigned:
        print(f"VM: {vm_name} already has a system-assigned managed identity enabled. Proceeding with the script.")
    else:
        print(f"Enabling system-assigned managed identity for VM: {vm_name}")
        vm.identity = VirtualMachineIdentity(type=ResourceIdentityType.system_assigned)
        async_vm_update = compute_client.virtual_machines.begin_create_or_update(resource_group_name, vm_name, vm)
        async_vm_update.result()
        print(f"System-assigned managed identity enabled for VM: {vm_name}")

def check_tag_subscription(subscription_id, credential):
    resource_client = ResourceManagementClient(credential, subscription_id)
    subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
    tags = subscription_tags.properties.tags
    if tags.get(SUBSCRIPTION_TAG[0]) == SUBSCRIPTION_TAG[1]:
        print(f"Subscription {subscription_id} has the required tags. Proceeding.")
        return True
    else:
        print(f"Subscription {subscription_id} does not have the required tags. Skipping")
        return False

def install_vm_extension(compute_client, extension_name, vm, vm_name, resource_group):
    extension_parameters = {
        "location": vm.location,
        "publisher": "Microsoft.Azure.Monitor",
        "type": extension_name,
        "type_handler_version": "1.10",
        "auto_upgrade_minor_version": True,
        "settings": {}
    }
    extensions_result = compute_client.virtual_machine_extensions.list(resource_group, vm_name)
    extensions = extensions_result.value  # Access the list of extensions
    if not extensions or any(extension.name not in ["AzureMonitorWindowsAgent", "AzureMonitorLinuxAgent"] for extension in extensions):
        print(f"No Azure Monitor Agent extension found on VM {vm_name}. Proceeding with installation.")
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
    else:
        print(f"{extension_name} already installed on VM {vm_name}.")

def associate_data_collection_rule(monitor_client, vm, vm_name):
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

def process_vm(vm, compute_client, monitor_client, subscription_id, credential):
    vm_name = vm.name
    resource_group = vm.id.split("/")[4]
    instance_view = compute_client.virtual_machines.instance_view(resource_group, vm_name)
    
    is_running = any(status.code == 'PowerState/running' for status in instance_view.statuses)
    
    if not is_running:
        print(f"VM {vm_name} is not running. Skipping.")
        return

    print(f"VM {vm_name} is running. Proceeding with installation of Azure Monitor agent.")
    
    tags = vm.tags
    os_profile = vm.os_profile
    
    if tags and tags.get(VM_TAG[0]) == VM_TAG[1] or all(element == "" for element in VM_TAG):
        enable_system_assigned_identity(resource_group, vm.name, subscription_id, credential)
        if os_profile.windows_configuration:
            install_vm_extension(compute_client, "AzureMonitorWindowsAgent", vm, vm_name, resource_group)
        elif os_profile.linux_configuration:
            install_vm_extension(compute_client, "AzureMonitorLinuxAgent", vm, vm_name, resource_group)
        else:
            print(f"VM {vm_name} has an unsupported OS. Skipping.")
            return
        
        associate_data_collection_rule(monitor_client, vm, vm_name)
    else:
        print(f"VM {vm_name} does not have the required tags. Skipping.")

def process_subscription(subscription, credential):
    subscription_id = subscription.subscription_id
    print(f"Processing subscription: {subscription_id}")
    
    compute_client = ComputeManagementClient(credential, subscription_id)
    monitor_client = MonitorManagementClient(credential, subscription_id)
    
    for vm in compute_client.virtual_machines.list_all():
        process_vm(vm, compute_client, monitor_client, subscription_id, credential)

def main():
    # Authenticate using the service principal
    credential = ClientSecretCredential(tenant_id=TENANT_ID, client_id=CLIENT_ID, client_secret=CLIENT_SECRET)

    # Get a list of subscriptions
    subscription_client = SubscriptionClient(credential)
    
    for subscription in subscription_client.subscriptions.list():
        if check_tag_subscription(subscription.subscription_id, credential) or all(element == "" for element in SUBSCRIPTION_TAG):
            process_subscription(subscription, credential)

if __name__ == "__main__":
    main()