import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, AsyncMock
from src.compliance.reporting import ()
ComplianceManager,
ComplianceFramework,
ComplianceCheck,
ComplianceStatus,
ComplianceReport,
ComplianceValidator,
ReportGenerator,
)


class TestComplianceFramework:
    def test_framework_enum_values(self):
        assert ComplianceFramework.PCI_DSS.value == "PCI-DSS"
        assert ComplianceFramework.HIPAA.value == "HIPAA"
        assert ComplianceFramework.SOC2.value == "SOC2"
        assert ComplianceFramework.ISO_27001.value == "ISO-27001"
        assert ComplianceFramework.NIST.value == "NIST"
        assert ComplianceFramework.CIS.value == "CIS"


        class TestComplianceCheck:
            def test_compliance_check_creation(self):
                check = ComplianceCheck()
                control_id="PCI-2.3",
                description="Encrypt all non-console administrative access",
                status=ComplianceStatus.COMPLIANT,
                evidence=["SSH enabled", "Telnet disabled"],
                device_id="router1",
                timestamp=datetime.now(),
                )

                assert check.control_id == "PCI-2.3"
                assert check.status == ComplianceStatus.COMPLIANT
                assert len(check.evidence) == 2

                def test_non_compliant_check(self):
                    check = ComplianceCheck()
                    control_id="HIPAA-164.312",
                    description="Encryption at rest",
                    status=ComplianceStatus.NON_COMPLIANT,
                    evidence=["Unencrypted backup found"],
                    remediation="Enable backup encryption",
                    device_id="switch1",
                    timestamp=datetime.now(),
                    )

                    assert check.status == ComplianceStatus.NON_COMPLIANT
                    assert check.remediation is not None


                    class TestComplianceValidator:
                        @pytest.mark.asyncio
                        async def test_validate_pci_dss_controls(self):
                            validator = ComplianceValidator()

                            device_config = {}
                            "hostname": "router1",
                            "interfaces": []
                            {"name": "GigabitEthernet0/0", "encryption": "ipsec"},
                            {"name": "GigabitEthernet0/1", "encryption": None},
                            ],
                            "ssh": {"enabled": True, "version": 2},
                            "telnet": {"enabled": False},
                            "snmp": {"version": 3, "encryption": "aes256"},
                            "logging": {"enabled": True, "remote_server": "10.0.0.100"},
                            "ntp": {"enabled": True, "authentication": True},
                            "password_policy": {}
                            "min_length": 12,
                            "complexity": True,
                            "expiry_days": 90,
                            },
                            }

                            checks = await validator.validate_pci_dss(device_config)

                            assert len(checks) > 0

        # Check specific controls
                            ssh_check = next((c for c in checks if "SSH" in c.description), None)
                            assert ssh_check is not None
                            assert ssh_check.status == ComplianceStatus.COMPLIANT

                            @pytest.mark.asyncio
                            async def test_validate_hipaa_controls(self):
                                validator = ComplianceValidator()

                                device_config = {}
                                "hostname": "switch1",
                                "encryption": {"data_at_rest": True, "data_in_transit": True},
                                "access_control": {}
                                "unique_user_ids": True,
                                "automatic_logoff": 15,
                                "encryption_decryption": True,
                                },
                                "audit_controls": {}
                                "enabled": True,
                                "log_retention_days": 180,
                                "integrity_controls": True,
                                },
                                "backup": {}
                                "enabled": True,
                                "encrypted": True,
                                "tested": datetime.now() - timedelta(days=30),
                                },
                                }

                                checks = await validator.validate_hipaa(device_config)

                                assert len(checks) > 0

        # Verify access controls
                                access_check = next()
                                (c for c in checks if "164.312(a)" in c.control_id),
                                None
                                )
                                assert access_check is not None

                                @pytest.mark.asyncio
                                async def test_validate_cis_benchmarks(self):
                                    validator = ComplianceValidator()

                                    device_config = {}
                                    "hostname": "firewall1",
                                    "services": {}
                                    "unnecessary_services": [],
                                    "source_routing": False,
                                    "ip_forwarding": True,
                                    "proxy_arp": False,
                                    },
                                    "passwords": {"encrypted": True,}
                                    "min_length": 14
                                    "lockout_attempts": 5}

                                    "banner": {}
                                    "login": "Authorized access only",
                                    "motd": "This system is monitored",
                                    },
                                    "snmp": {"enabled": True,}
                                    "version": 3
                                    "default_community": False}

                                    }

                                    checks = await validator.validate_cis(device_config)

                                    assert len(checks) > 0

        # Check password controls
                                    password_check = next()
                                (c for c in checks if "password" in c.description.lower()), None
                                )
                                assert password_check is not None


                                class TestComplianceManager:
                                    @pytest.mark.asyncio
                                    async def test_check_compliance_single_framework(self):
                                        manager = ComplianceManager()

        # Mock device configurations
                                        with patch.object(:):
                                        manager, "_get_device_configs", new_callable=AsyncMock
                                        ) as mock_configs:
                                            mock_configs.return_value = []
                                            {}
                                            "device_id": "router1",
                                            "hostname": "core-router",
                                            "ssh": {"enabled": True, "version": 2},
                                            "telnet": {"enabled": False},
                                            "password_policy": {"min_length": 12},
                                            }
                                            ]

                                            checks = await manager.check_compliance()
                                            framework=ComplianceFramework.PCI_DSS, device_ids=["router1"]
                                            )

                                            assert len(checks) > 0
                                            assert all(c.device_id == "router1" for c in checks)

                                            @pytest.mark.asyncio
                                            async def test_check_compliance_multiple_devices(self):
                                                manager = ComplianceManager()

                                                with patch.object(:):
                                                manager, "_get_device_configs", new_callable=AsyncMock
                                                ) as mock_configs:
                                                    mock_configs.return_value = []
                                                    {}
                                                    "device_id": "router1",
                                                    "hostname": "router1",
                                                    "ssh": {"enabled": True},
                                                    },
                                                    {}
                                                    "device_id": "switch1",
                                                    "hostname": "switch1",
                                                    "ssh": {"enabled": False},
                                                    },
                                                    ]

                                                    checks = await manager.check_compliance()
                                                    framework=ComplianceFramework.CIS,
                                                    device_ids=["router1"]
                                                    "switch1"]
                                                    )

            # Should have checks for both devices
                                                    device_ids = {check.device_id for check in checks}
                                                    assert "router1" in device_ids
                                                    assert "switch1" in device_ids

                                                    @pytest.mark.asyncio
                                                    async def test_generate_compliance_report(self):
                                                        manager = ComplianceManager()

        # Mock historical checks
                                                        with patch.object(:):
                                                        manager, "_get_historical_checks", new_callable=AsyncMock
                                                        ) as mock_history:
                                                            mock_history.return_value = []
                                                            ComplianceCheck()
                                                            control_id="PCI-1.1",
                                                            description="Firewall configuration",
                                                            status=ComplianceStatus.COMPLIANT,
                                                            evidence=["Firewall rules reviewed"],
                                                            device_id="fw1",
                                                            timestamp=datetime.now(),
                                                            ),
                                                            ComplianceCheck()
                                                            control_id="PCI-2.3",
                                                            description="Encrypt admin access",
                                                            status=ComplianceStatus.NON_COMPLIANT,
                                                            evidence=["Telnet enabled"],
                                                            remediation="Disable telnet",
                                                            device_id="switch1",
                                                            timestamp=datetime.now(),
                                                            ),
                                                            ]

                                                            report = await manager.generate_report()
                                                            framework=ComplianceFramework.PCI_DSS,
                                                            start_date=datetime.now() - timedelta(days=30),
                                                            end_date=datetime.now(),
                                                            )

                                                            assert report.framework == ComplianceFramework.PCI_DSS
                                                            assert report.total_checks == 2
                                                            assert report.compliant_checks == 1
                                                            assert report.non_compliant_checks == 1
                                                            assert report.compliance_percentage == 50.0

                                                            @pytest.mark.asyncio
                                                            async def test_generate_executive_summary(self):
                                                                manager = ComplianceManager()

                                                                report = ComplianceReport()
                                                                framework=ComplianceFramework.SOC2,
                                                                start_date=datetime.now() - timedelta(days=30),
                                                                end_date=datetime.now(),
                                                                total_checks=100,
                                                                compliant_checks=85,
                                                                non_compliant_checks=10,
                                                                not_applicable_checks=5,
                                                                compliance_percentage=85.0,
                                                                checks=[],
                                                                summary={},
                                                                recommendations=["Implement MFA", "Update firewall rules"],
                                                                )

                                                                summary = manager._generate_executive_summary(report)

                                                                assert "SOC2" in summary
                                                                assert "85.0%" in summary
                                                                assert "100" in summary

                                                                def test_export_report_json(self):
                                                                    manager = ComplianceManager()

                                                                    report = ComplianceReport()
                                                                    framework=ComplianceFramework.ISO_27001,
                                                                    start_date=datetime.now() - timedelta(days=7),
                                                                    end_date=datetime.now(),
                                                                    total_checks=50,
                                                                    compliant_checks=45,
                                                                    non_compliant_checks=5,
                                                                    not_applicable_checks=0,
                                                                    compliance_percentage=90.0,
                                                                    checks=[]
                                                                    ComplianceCheck()
                                                                    control_id="A.12.1",
                                                                    description="Operational procedures",
                                                                    status=ComplianceStatus.COMPLIANT,
                                                                    evidence=["Procedures documented"],
                                                                    device_id="all",
                                                                    timestamp=datetime.now(),
                                                                    )
                                                                    ],
                                                                    summary={"category": "Operations"},
                                                                    recommendations=["Review quarterly"],
                                                                    )

                                                                    json_output = manager.export_report(report, format="json")
                                                                    data = json.loads(json_output)

                                                                    assert data["framework"] == "ISO-27001"
                                                                    assert data["compliance_percentage"] == 90.0
                                                                    assert len(data["checks"]) == 1

                                                                    def test_export_report_html(self):
                                                                        manager = ComplianceManager()

                                                                        report = ComplianceReport()
                                                                        framework=ComplianceFramework.NIST,
                                                                        start_date=datetime.now() - timedelta(days=30),
                                                                        end_date=datetime.now(),
                                                                        total_checks=75,
                                                                        compliant_checks=70,
                                                                        non_compliant_checks=5,
                                                                        not_applicable_checks=0,
                                                                        compliance_percentage=93.33,
                                                                        checks=[],
                                                                        summary={},
                                                                        recommendations=[],
                                                                        )

                                                                        html_output = manager.export_report(report, format="html")

                                                                        assert "<html>" in html_output
                                                                        assert "NIST" in html_output
                                                                        assert "93.33%" in html_output
                                                                        assert "Compliance Report" in html_output

                                                                        def test_export_report_csv(self):
                                                                            manager = ComplianceManager()

                                                                            report = ComplianceReport()
                                                                            framework=ComplianceFramework.CIS,
                                                                            start_date=datetime.now() - timedelta(days=7),
                                                                            end_date=datetime.now(),
                                                                            total_checks=25,
                                                                            compliant_checks=20,
                                                                            non_compliant_checks=5,
                                                                            not_applicable_checks=0,
                                                                            compliance_percentage=80.0,
                                                                            checks=[]
                                                                            ComplianceCheck()
                                                                            control_id="CIS-1.1",
                                                                            description="Disable unused services",
                                                                            status=ComplianceStatus.COMPLIANT,
                                                                            evidence=["All services reviewed"],
                                                                            device_id="server1",
                                                                            timestamp=datetime.now(),
                                                                            )
                                                                            ],
                                                                            summary={},
                                                                            recommendations=[],
                                                                            )

                                                                            csv_output = manager.export_report(report, format="csv")

                                                                            assert "Control ID,Description,Status,Device,Evidence,Remediation" in \
                                                                            csv_output
                                                                            assert "CIS-1.1" in csv_output
                                                                            assert "COMPLIANT" in csv_output


                                                                            class TestReportGenerator:
                                                                                def test_generate_html_report(self):
                                                                                    generator = ReportGenerator()

                                                                                    report = ComplianceReport()
                                                                                    framework=ComplianceFramework.PCI_DSS,
                                                                                    start_date=datetime.now() - timedelta(days=30),
                                                                                    end_date=datetime.now(),
                                                                                    total_checks=100,
                                                                                    compliant_checks=92,
                                                                                    non_compliant_checks=8,
                                                                                    not_applicable_checks=0,
                                                                                    compliance_percentage=92.0,
                                                                                    checks=[]
                                                                                    ComplianceCheck()
                                                                                    control_id="PCI-1.1",
                                                                                    description="Firewall standards",
                                                                                    status=ComplianceStatus.COMPLIANT,
                                                                                    evidence=["Standards documented"],
                                                                                    device_id="fw1",
                                                                                    timestamp=datetime.now(),
                                                                                    )
                                                                                    ],
                                                                                    summary={"critical_findings": 2},
                                                                                    recommendations=["Review firewall rules monthly"],
                                                                                    )

                                                                                    html = generator.generate_html(report)

                                                                                    assert "<!DOCTYPE html>" in html
                                                                                    assert "PCI-DSS Compliance Report" in html
                                                                                    assert "92.0%" in html
                                                                                    assert "PCI-1.1" in html

                                                                                    def test_generate_csv_report(self):
                                                                                        generator = ReportGenerator()

                                                                                        checks = []
                                                                                        ComplianceCheck()
                                                                                        control_id="HIPAA-164.308",
                                                                                        description="Administrative safeguards",
                                                                                        status=ComplianceStatus.COMPLIANT,
                                                                                        evidence=["Policies in place"],
                                                                                        device_id="all",
                                                                                        timestamp=datetime.now(),
                                                                                        ),
                                                                                        ComplianceCheck()
                                                                                        control_id="HIPAA-164.310",
                                                                                        description="Physical safeguards",
                                                                                        status=ComplianceStatus.NON_COMPLIANT,
                                                                                        evidence=["No physical access logs"],
                                                                                        remediation="Implement access logging",
                                                                                        device_id="datacenter",
                                                                                        timestamp=datetime.now(),
                                                                                        ),
                                                                                        ]

                                                                                        csv = generator.generate_csv(checks)
                                                                                        lines = csv.strip().split("\n")

                                                                                        assert len(lines) == 3  # Header + 2 checks
                                                                                        assert "HIPAA-164.308" in lines[1]
                                                                                        assert "NON_COMPLIANT" in lines[2]


                                                                                        class TestComplianceIntegration:
                                                                                            @pytest.mark.asyncio
                                                                                            async def test_end_to_end_compliance_workflow(self):
                                                                                                """Test complete compliance checking and reporting workflow"""

                                                                                                manager = ComplianceManager()

        # Mock device configurations
                                                                                                with patch.object(:):
                                                                                                manager, "_get_device_configs", new_callable=AsyncMock
                                                                                                ) as mock_configs:
                                                                                                    mock_configs.return_value = []
                                                                                                    {}
                                                                                                    "device_id": "router1",
                                                                                                    "hostname": "core-router",
                                                                                                    "ssh": {"enabled": True, "version": 2},
                                                                                                    "telnet": {"enabled": False},
                                                                                                    "snmp": {"version": 3, "encryption": "aes256"},
                                                                                                    "logging": {"enabled": True, "remote_server": "10.0.0.1"},
                                                                                                    "password_policy": {}
                                                                                                    "min_length": 14,
                                                                                                    "complexity": True,
                                                                                                    "expiry_days": 90,
                                                                                                    },
                                                                                                    "backup": {}
                                                                                                    "enabled": True,
                                                                                                    "encrypted": True,
                                                                                                    "frequency": "daily",
                                                                                                    },
                                                                                                    }
                                                                                                    ]

            # Run compliance check
                                                                                                    checks = await manager.check_compliance()
                                                                                                    framework=ComplianceFramework.PCI_DSS, device_ids=["router1"]
                                                                                                    )

                                                                                                    assert len(checks) > 0

            # Generate report
                                                                                                    with patch.object(:):
                                                                                                    manager, "_get_historical_checks", new_callable=AsyncMock
                                                                                                    ) as mock_history:
                                                                                                        mock_history.return_value = checks

                                                                                                        report = await manager.generate_report()
                                                                                                        framework=ComplianceFramework.PCI_DSS,
                                                                                                        start_date=datetime.now() - timedelta(days=30),
                                                                                                        end_date=datetime.now(),
                                                                                                        device_ids=["router1"],
                                                                                                        )

                                                                                                        assert report.framework == ComplianceFramework.PCI_DSS
                                                                                                        assert report.total_checks > 0
                                                                                                        assert report.compliance_percentage >= 0

                # Export in different formats
                                                                                                        json_export = manager.export_report(report, format="json")
                                                                                                        assert json.loads(json_export)  # Valid JSON

                                                                                                        html_export = manager.export_report(report, format="html")
                                                                                                        assert "<html>" in html_export

                                                                                                        csv_export = manager.export_report(report, format="csv")
                                                                                                        assert "Control ID" in csv_export

                                                                                                        @pytest.mark.asyncio
                                                                                                        async def test_multi_framework_compliance(self):
                                                                                                            """Test compliance checking across multiple frameworks"""

                                                                                                            manager = ComplianceManager()

                                                                                                            device_config = {}
                                                                                                            "device_id": "switch1",
                                                                                                            "hostname": "access-switch",
                                                                                                            "ssh": {"enabled": True, "version": 2},
                                                                                                            "encryption": {"data_at_rest": True, "data_in_transit": True},
                                                                                                            }

                                                                                                            with patch.object(:):
                                                                                                            manager, "_get_device_configs", new_callable=AsyncMock
                                                                                                            ) as mock_configs:
                                                                                                                mock_configs.return_value = [device_config]

                                                                                                                frameworks = []
                                                                                                                ComplianceFramework.PCI_DSS,
                                                                                                                ComplianceFramework.HIPAA,
                                                                                                                ComplianceFramework.CIS,
                                                                                                                ]

                                                                                                                all_checks = []

                                                                                                                for framework in frameworks:
                                                                                                                    checks = await manager.check_compliance()
                                                                                                                    framework=framework, device_ids=["switch1"]
                                                                                                                    )
                                                                                                                    all_checks.extend(checks)

            # Should have checks from all frameworks
                                                                                                                    assert len(all_checks) > 0

            # Verify different control IDs
                                                                                                                    control_prefixes = {check.control_id.split("-")[0] for check in}
                                                                                                                    all_checks}
                                                                                                                    assert len(control_prefixes) >= 2  # Multiple framework prefixes

                                                                                                                    @pytest.mark.asyncio
                                                                                                                    async def test_compliance_trend_analysis(self):
                                                                                                                        """Test compliance trend analysis over time"""

                                                                                                                        manager = ComplianceManager()

        # Simulate historical compliance data
                                                                                                                        historical_reports = []

                                                                                                                        for i in range(30, 0, -7):  # Weekly reports for past month:
                                                                                                                            report = ComplianceReport()
                                                                                                                            framework=ComplianceFramework.SOC2,
                                                                                                                            start_date=datetime.now() - timedelta(days=i),
                                                                                                                            end_date=datetime.now() - timedelta(days=i - 7),
                                                                                                                            total_checks=100,
                                                                                                                            compliant_checks=90 + i // 10,  # Improving trend
                                                                                                                            non_compliant_checks=10 - i // 10,
                                                                                                                            not_applicable_checks=0,
                                                                                                                            compliance_percentage=90 + i / 10,
                                                                                                                            checks=[],
                                                                                                                            summary={},
                                                                                                                            recommendations=[],
                                                                                                                            )
                                                                                                                            historical_reports.append(report)

        # Analyze trend
                                                                                                                            trend = manager.analyze_compliance_trend(historical_reports)

                                                                                                                            assert trend["improvement"] > 0
                                                                                                                            assert trend["current_compliance"] > trend["initial_compliance"]
