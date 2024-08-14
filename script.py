import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import DataCollectionRuleAssociationProxyOnlyResource
from azure.core.exceptions import HttpResponseError

load_dotenv()

# Retrieve the credentials from environment variables
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DATA_COLLECTION_RULE_ID = os.getenv("DATA_COLLECTION_RULE_ID")
CLIENT_ID_AMA = os.getenv("CLIENT_ID_AMA")

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
        ).result()
        print(f"{extension_name} installed on VM {vm_name}.")
    except HttpResponseError as e:
        print(f"Failed to install {extension_name} on VM {vm_name}. Error: {e}")

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

def process_vm(vm, compute_client, monitor_client, subscription_id):
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
    
    if tags and tags.get("amainstall") == "true":
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
        process_vm(vm, compute_client, monitor_client, subscription_id)

def main():
    # Authenticate using the service principal
    credential = ClientSecretCredential(tenant_id=TENANT_ID, client_id=CLIENT_ID, client_secret=CLIENT_SECRET)

    # Get a list of subscriptions
    subscription_client = SubscriptionClient(credential)
    
    for subscription in subscription_client.subscriptions.list():
        process_subscription(subscription, credential)

if __name__ == "__main__":
    main()