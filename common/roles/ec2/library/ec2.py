#!/usr/bin/python

import boto3
from ansible.module_utils.basic import *

def get_instance(conn, name):
    try:
        return ec2.instances.filter(Filters=[{'tag:Name': name}])[0]
    except Exception:
        return None

def create_instance(ec2, image_id):
    return ec2.create_instances(ImageId=image_id, MinCount=1, MaxCount=5)

def create_vpc_subnet_gateway(ec2):
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/24')
    subnet = vpc.create_subnet(CidrBlock='10.0.0.0/25')
    gateway = ec2.create_internet_gateway()
    return (vpc, subnet, gateway)

def enable_or_disable_monitor(ec2, instance_ids=[], is_enable=True):
    if is_enable:
        return ec2.monitor_instances(InstanceIds=instance_ids)
    else:
        return ec2.unmonitor_instances(InstanceIds=instance_ids)

def attach_and_detach_elasticip_and_gateway(ec2, vpc, gateway):
    gateway.attach_to_vpc(VpcId=vpc.id)
    gateway.detach_from_vpc(VpcId=vpc.id)

    address = ec2.VpcAddress('eipalloc-35cf685d')
    address.associate('i-71b2f60b')
    address.association.delete()

def stop_instances(ec2, instanceIds = []):
    return ec2.instances.filter(InstanceIds=instanceIds).stop()

def terminate(ec2, instanceIds = []):
    return ec2.instances.filter(InstanceIds=instanceIds).terminate()

def manage_instances(instance_ids = [], action = 'start'):
    ec2 = boto3.client('ec2')
    if (action == 'start'):
        # Do a dryrun first to verify permissions
        try:
            ec2.start_instances(InstanceIds=instance_ids, DryRun=True)
        except ClientError as e:
            if 'DryRunOperation' not in str(e):
                raise

        # Dry run succeeded, run start_instances without dryrun
        try:
            return ec2.start_instances(InstanceIds=instance_ids, DryRun=False)
        except ClientError as e:
            print(e)
    elif (action == 'reboot'):
        try:
            ec2.reboot_instances(InstanceIds=instance_ids, DryRun=True)
        except ClientError as e:
            if 'DryRunOperation' not in str(e):
                print("You don't have permission to reboot instances.")
                raise

        try:
            response = ec2.reboot_instances(InstanceIds=instance_ids, DryRun=False)
        except ClientError as e:
            print('Error', e)
    elif (action == 'terminate'):
        try:
            ec2.terminate_instances(InstanceIds=instance_ids, DryRun=True)
        except ClientError as e:
            if 'DryRunOperation' not in str(e):
                print("You don't have permission to terminate instances.")
                raise

        try:
            response = ec2.terminate_instances(InstanceIds=instance_ids, DryRun=False)
        except ClientError as e:
            print('Error', e)
    else:
        # Do a dryrun first to verify permissions
        try:
            ec2.stop_instances(InstanceIds=[instance_id], DryRun=True)
        except ClientError as e:
            if 'DryRunOperation' not in str(e):
                raise

        # Dry run succeeded, call stop_instances witout dryrun
        try:
            return ec2.stop_instances(InstanceIds=[instance_id], DryRun=False)
        except ClientError as e:
            print(e)

def manage_key_pair(ec2, key_pair_name, action = 'create'):
    if (action == 'create'):
        return ec2.create_key_pair(KeyName=key_pair_name)
    else:
        return ec2.delete_key_pair(KeyName=key_pair_name)

def create_security_group_rule(ec2, group_name, description):
    response = ec2.describe_vpcs()
    vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

    try:
        response = ec2.create_security_group(GroupName=group_name, Description=description, VpcId=vpc_id)
        security_group_id = response['GroupId']
        print('Security Group Created %s in vpc %s.' % (security_group_id, vpc_id))

        data = ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                { 'IpProtocol': 'tcp',
                  'FromPort': 80,
                  'ToPort': 80,
                  'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                { 'IpProtocol': 'tcp',
                  'FromPort': 22,
                  'ToPort': 22,
                  'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        ])
        print('Ingress Successfully Set %s' % data)
    except ClientError as e:
        print(e)

def delete_security_group(ec2, security_group_id):
    try:
        return ec2.delete_security_group(GroupId=security_group_id)
        print('Security Group Deleted')
    except ClientError as e:
        print(e)

def allocate_and_associate_elastic_ip(ec2, allocation_id, instance_id):
    try:
        allocation = ec2.allocate_address(Domain='vpc')
        return ec2.associate_address(AllocationId=allocation[allocation_id], InstanceId=instance_id)
    except ClientError as e:
        print(e)

def relase_elastic_ip(ec2, allication_id):
    try:
        return ec2.release_address(AllocationId=allication_id)
    except ClientError as e:
        print(e)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True),
            aws_secret_key=dict(required=True, no_log=True),
            aws_access_key=dict(required=True, no_log=True),
            security_token=dict(required=True, no_log=True),
            state=dict(default='running', choices=['running', 'stopped'])
        ),
        supports_check_mode=True
    )

    state = module.params.get('state')
    name = module.params.get('name')

    try:
        ec2 = boto3.resource('ec2')
        ec2.create_instances()
        instance = get_instance(conn, name)
        change_needed = instance.state != state
        if (not module.check_mode and change_needed):
            if (state == 'running'):
                conn.start_instances(instance_ids=[instance.id])
            else:
                conn.stop_instances(instance_ids=[instance.id])
            module.exit_json(changed=True, **return_creds)
        else:
            module.exit_json(changed=change_needed)
    except Exception as e:
        module.fail_json(msg='Error occurred. %s: %s' % (type(e), e.message))


main()