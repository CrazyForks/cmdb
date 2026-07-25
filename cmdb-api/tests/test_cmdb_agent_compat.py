# -*- coding:utf-8 -*-

from types import SimpleNamespace
from unittest.mock import patch


def test_historical_instances_for_agent_diff(app):
    from api.lib.cmdb.auto_discovery.auto_discovery import AutoDiscoveryCICRUD

    rows = [SimpleNamespace(unique_value='host-1'), SimpleNamespace(unique_value='host-2')]
    with patch('api.lib.cmdb.auto_discovery.auto_discovery.AutoDiscoveryCIType.get_by_id', return_value=True), \
            patch.object(AutoDiscoveryCICRUD.cls, 'get_by', return_value=rows):
        assert AutoDiscoveryCICRUD.get_instances_by_adt_id(7) == ['host-1', 'host-2']


def test_scan_rules_are_converted_to_current_agent_format(app):
    from api.lib.cmdb.ipam.subnet import SubnetManager

    manager = SubnetManager.__new__(SubnetManager)
    manager.type_id = 10
    rules = [{
        'id': 3,
        'ci_id': 20,
        'agent_id': '0x0001',
        'cron': '*/5 * * * *',
        'scan_enabled': True,
        'rule_updated_at': '2026-07-25 10:00:00',
        'created_at': '2026-07-25 09:00:00',
    }]

    with patch('api.lib.cmdb.ipam.subnet.IPAMSubnetScan.get_by', return_value=rules), \
            patch('api.lib.cmdb.ipam.subnet.SearchFromDB') as search, \
            patch('api.lib.cmdb.ipam.subnet.SystemConfigManager.get', return_value=None):
        search.return_value.search.return_value = ([{'_id': 20, 'cidr': '10.0.0.0/24'}], 0, None, None, None, None)
        result, updated_at = manager.scan_rules('0x0001')

    assert updated_at == '2026-07-25 10:00:00'
    assert result == [{
        'rule_id': 3,
        'rule_name': 'subnet_20',
        'agent_id': '0x0001',
        'cron': '*/5 * * * *',
        'max_concurrent': 1,
        'scan_enabled': True,
        'ping_enabled': True,
        'port_scan_enabled': False,
        'port_list': [],
        'scan_mode': 'active',
        'subnets': [{'ci_id': 20, 'cidr': '10.0.0.0/24'}],
        'rule_updated_at': '2026-07-25 10:00:00',
        'created_at': '2026-07-25 09:00:00',
    }]


def test_current_agent_scan_result_is_saved_in_community_history(app):
    from api.lib.cmdb.ipam.subnet import SubnetManager

    manager = SubnetManager.__new__(SubnetManager)
    manager.type_id = 10
    rule = SimpleNamespace(id=3, ci_id=20)
    payload = {
        '20': {
            'cidr': '10.0.0.0/24',
            'active_ips': ['10.0.0.2'],
            'status': 0,
        }
    }

    with patch('api.lib.cmdb.ipam.subnet.IPAMSubnetScan.get_by_id', return_value=rule), \
            patch('api.lib.cmdb.ipam.subnet.SearchFromDB') as search, \
            patch('api.lib.cmdb.ipam.subnet.ScanHistoryManager') as history:
        search.return_value.search.return_value = ([{'_id': 20, 'cidr': '10.0.0.0/24'}], 0, None, None, None, None)
        manager.save_scan_results(3, 'exec-1', payload, status=0)

    history.return_value.add.assert_called_once_with(
        subnet_scan_id=3,
        exec_id='exec-1',
        ci_id=20,
        cidr='10.0.0.0/24',
        start_at=None,
        end_at=None,
        status=0,
        stdout=None,
        ip_num=1,
        ips=['10.0.0.2'])
