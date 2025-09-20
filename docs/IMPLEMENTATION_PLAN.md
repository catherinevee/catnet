# CatNet Implementation Plan

## Overview
This plan outlines phased improvements to CatNet's core functionality, ensuring GitHub Actions workflows pass after each phase. Each phase delivers working functionality without over-engineering.

## Guiding Principles
- ✅ **Keep It Simple** - Implement only what's needed
- ✅ **Tests Must Pass** - Each phase must maintain passing CI/CD
- ✅ **Incremental Value** - Each phase adds usable functionality
- ✅ **No Over-Engineering** - Avoid complex systems until proven necessary
- ✅ **Quick Validation** - Test and validate at each step

---

## Phase 1: Fix Foundation (Week 1)
**Goal**: Make existing tests pass and basic API functional

### Tasks
1. **Fix Database Relationships** ⚡ Priority: Critical
   - [ ] Fix User-Deployment foreign key ambiguity
   - [ ] Add explicit relationship definitions
   - [ ] Ensure all models can be instantiated
   - **Success Metric**: `pytest tests/test_models.py` passes

2. **Fix Authentication Flow** ⚡ Priority: Critical
   - [ ] Resolve login endpoint database errors
   - [ ] Ensure JWT tokens generate correctly
   - [ ] Add simple session storage (in-memory is fine)
   - **Success Metric**: `/api/v1/auth/login` returns token

3. **Stabilize CI/CD**
   - [ ] Ensure all existing tests pass
   - [ ] Fix import errors
   - [ ] Update requirements.txt with missing packages
   - **Success Metric**: GitHub Actions green ✅

### Deliverables
- Working authentication
- Passing test suite
- Stable API startup

### Validation
```bash
# All these must work:
pytest tests/
python run_catnet.py  # Starts without errors
curl -X POST http://localhost:8002/api/v1/auth/login  # Returns response
```

---

## Phase 2: Minimal Device Management (Week 2)
**Goal**: Add ability to manage device inventory

### Tasks
1. **Simple Device Storage**
   - [ ] Add in-memory device store (no complex DB yet)
   - [ ] Create device model with basic fields (id, ip, vendor, username)
   - [ ] Implement CRUD endpoints
   ```python
   # Simple implementation:
   device_store = {}  # Start simple, upgrade later if needed
   ```

2. **Device API Endpoints**
   - [ ] POST /api/v1/devices - Add device
   - [ ] GET /api/v1/devices - List devices
   - [ ] GET /api/v1/devices/{id} - Get device
   - [ ] DELETE /api/v1/devices/{id} - Remove device

3. **Basic Credential Management**
   - [ ] Add encrypted file storage for credentials (using cryptography)
   - [ ] No Vault required initially
   - [ ] Simple key-value store
   ```yaml
   # config/credentials.yaml (encrypted)
   devices:
     router1:
       username: admin
       password: !encrypted:xxxxx
   ```

### Deliverables
- Device management API
- Secure credential storage
- Device listing in CLI

### Validation
```bash
# Add a device
curl -X POST http://localhost:8002/api/v1/devices \
  -d '{"id": "router1", "ip": "192.168.1.1", "vendor": "cisco_ios"}'

# List devices
python catnet_cli.py device list
```

---

## Phase 3: Basic GitHub Integration (Week 3)
**Goal**: Pull configurations from GitHub

### Tasks
1. **Simple GitHub Client**
   - [ ] Use PyGithub library (already in requirements)
   - [ ] Connect to public repos (no auth initially)
   - [ ] List and retrieve config files
   ```python
   # Keep it simple:
   def get_config_from_github(repo, path):
       return requests.get(f"https://raw.githubusercontent.com/{repo}/main/{path}").text
   ```

2. **GitOps Endpoints**
   - [ ] GET /api/v1/gitops/configs - List configs in repo
   - [ ] GET /api/v1/gitops/configs/{path} - Get specific config
   - [ ] POST /api/v1/gitops/connect - Store repo URL

3. **Config Storage**
   - [ ] Cache configs locally
   - [ ] Simple file-based storage
   - [ ] No complex sync needed yet

### Deliverables
- GitHub repository connection
- Config retrieval from GitHub
- Local config cache

### Validation
```bash
# Connect to repo
python catnet_cli.py gitops connect --repo catherinevee/network-configs

# List configs
python catnet_cli.py gitops list-configs
```

---

## Phase 4: Minimal Deployment Pipeline (Week 4)
**Goal**: Connect GitHub → CatNet → Device (simulation)

### Tasks
1. **Wire Components Together**
   - [ ] Connect GitOps → Deployment Service
   - [ ] Connect Deployment → Device Service
   - [ ] Create simple deployment flow
   ```python
   async def deploy_config(config_path, device_id):
       config = await gitops.get_config(config_path)
       device = await devices.get(device_id)
       return await deployment.deploy(config, device)
   ```

2. **Deployment Simulation Mode**
   - [ ] Add dry-run capability
   - [ ] Log what would be sent to device
   - [ ] No actual device connection yet
   ```python
   if dry_run:
       logger.info(f"Would send to {device}: {commands}")
       return {"status": "dry_run_success"}
   ```

3. **Basic Deployment Tracking**
   - [ ] In-memory deployment history
   - [ ] Simple status: pending → running → complete/failed
   - [ ] No complex state machine

### Deliverables
- End-to-end deployment flow (simulated)
- Deployment status tracking
- Dry-run capability

### Validation
```bash
# Deploy config to device (dry-run)
python catnet_cli.py deploy \
  --source github \
  --config configs/router1.cfg \
  --device router1 \
  --dry-run
```

---

## Phase 5: Real Device Connection (Week 5)
**Goal**: Actually connect and deploy to one device type

### Tasks
1. **Implement Cisco SSH Connector**
   - [ ] Use Netmiko for SSH connection
   - [ ] Start with basic commands only
   - [ ] Handle connection errors gracefully
   ```python
   def connect_cisco(device):
       try:
           return ConnectHandler(
               device_type='cisco_ios',
               host=device['ip'],
               username=device['username'],
               password=device['password']
           )
       except Exception as e:
           logger.error(f"Connection failed: {e}")
           return None
   ```

2. **Configuration Deployment**
   - [ ] Parse config into commands
   - [ ] Send commands one by one
   - [ ] Capture output
   - [ ] No complex validation yet

3. **Basic Backup**
   - [ ] Get running-config before changes
   - [ ] Store in local file
   - [ ] Simple timestamp-based naming

### Deliverables
- Working Cisco device connection
- Actual configuration deployment
- Basic backup before deployment

### Validation
```bash
# Deploy to real device (test environment)
python catnet_cli.py deploy \
  --source github \
  --config configs/test_vlan.cfg \
  --device test_switch \
  --no-dry-run
```

---

## Phase 6: Basic Rollback & Safety (Week 6)
**Goal**: Add safety mechanisms

### Tasks
1. **Simple Health Check**
   - [ ] Ping device after deployment
   - [ ] Check interface status
   - [ ] Basic connectivity test
   ```python
   def health_check(device):
       return device.is_alive()  # Start simple
   ```

2. **Manual Rollback**
   - [ ] Command to restore backup
   - [ ] No automatic triggers yet
   - [ ] User-initiated only
   ```bash
   python catnet_cli.py rollback --device router1 --backup backup_20240120.cfg
   ```

3. **Deployment Validation**
   - [ ] Compare expected vs actual
   - [ ] Simple diff check
   - [ ] Log discrepancies

### Deliverables
- Health check after deployment
- Manual rollback capability
- Configuration verification

### Validation
```bash
# Deploy with health check
python catnet_cli.py deploy --config test.cfg --device router1 --verify

# Rollback if needed
python catnet_cli.py rollback --device router1
```

---

## Phase 7: Monitoring & Observability (Week 7)
**Goal**: Know what's happening

### Tasks
1. **Structured Logging**
   - [ ] Add deployment logs
   - [ ] Include timestamp, device, status
   - [ ] Simple JSON format
   ```python
   logger.info(json.dumps({
       "event": "deployment",
       "device": device_id,
       "status": "success",
       "duration": elapsed_time
   }))
   ```

2. **Basic Metrics**
   - [ ] Deployment count
   - [ ] Success/failure rate
   - [ ] Simple in-memory counters
   - [ ] Expose at /metrics endpoint

3. **Deployment History API**
   - [ ] GET /api/v1/deployments/history
   - [ ] Last 100 deployments
   - [ ] Simple list, no complex queries

### Deliverables
- Deployment logging
- Basic metrics endpoint
- History viewing

### Validation
```bash
# View metrics
curl http://localhost:8002/metrics

# View deployment history
python catnet_cli.py deployment history
```

---

## Phase 8: Testing & Documentation (Week 8)
**Goal**: Ensure reliability and usability

### Tasks
1. **Integration Tests**
   - [ ] Test GitHub → Device flow
   - [ ] Mock device connections
   - [ ] Test rollback scenarios
   ```python
   def test_deployment_flow():
       # Simple, focused tests
       assert deploy_config("test.cfg", "mock_device") == "success"
   ```

2. **Update Documentation**
   - [ ] Update README with real examples
   - [ ] Add troubleshooting guide
   - [ ] Document all CLI commands

3. **Error Handling**
   - [ ] Graceful degradation
   - [ ] Clear error messages
   - [ ] No stack traces to users

### Deliverables
- Comprehensive test suite
- Updated documentation
- Improved error handling

### Validation
```bash
# All tests pass
pytest tests/ --cov=src --cov-report=term

# Documentation is helpful
python catnet_cli.py --help  # Shows all commands
```

---

## Success Criteria

### After Each Phase
- ✅ GitHub Actions workflows pass
- ✅ No regression in existing functionality
- ✅ New features are usable immediately
- ✅ Documentation updated

### Overall Project Success
- ✅ Can deploy config from GitHub to a real device
- ✅ Can rollback on failure
- ✅ All tests passing
- ✅ Basic monitoring in place

---

## Anti-Patterns Avoided

### ❌ We Will NOT
- Build complex distributed systems before proving single-node works
- Implement Kubernetes operators before basic deployment works
- Add ML features before core pipeline functions
- Create complex state machines when simple status tracking suffices
- Build elaborate rollback mechanisms before manual rollback works
- Implement multi-region support before single device deployment works

### ✅ We WILL
- Start with in-memory storage, add database when needed
- Use simple file-based configs before complex Vault integration
- Implement one device type well before adding others
- Build manual processes before automation
- Test with dry-run before real devices
- Add features only when previous phase works

---

## Risk Mitigation

### Technical Risks
- **Device damage**: Start with dry-run, test devices only
- **Network outages**: Manual rollback always available
- **Security**: Encrypted credentials from day one

### Project Risks
- **Scope creep**: Strict phase boundaries
- **Over-engineering**: Simple first, complex only if needed
- **Testing gaps**: Integration tests for each phase

---

## Maintenance Mode Features
*These are intentionally deferred to avoid over-engineering:*

- HashiCorp Vault integration (use encrypted files initially)
- Kubernetes operator (not needed for core function)
- ML anomaly detection (add after basics work)
- Multi-region deployment (single region first)
- Complex approval workflows (manual approval sufficient)
- Distributed tracing (simple logs sufficient initially)

---

## Phase Completion Checklist

Before moving to next phase:
- [ ] All tests passing
- [ ] GitHub Actions green
- [ ] Feature is usable via CLI
- [ ] Documentation updated
- [ ] No critical bugs
- [ ] Code reviewed and clean

---

## Timeline

- **Phase 1-2**: Foundation (Weeks 1-2) - Make it work
- **Phase 3-4**: Integration (Weeks 3-4) - Connect the pieces
- **Phase 5-6**: Real Deployment (Weeks 5-6) - Actually deploy
- **Phase 7-8**: Polish (Weeks 7-8) - Make it reliable

**Total: 8 weeks to working system**

---

## Notes

This plan prioritizes:
1. **Working software** over perfect architecture
2. **Simple solutions** over complex systems
3. **Incremental delivery** over big bang releases
4. **Proven needs** over anticipated requirements

Each phase delivers value and maintains a working system.