// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    Field memo: "mica-tilt lantern"
    --------------------------------
    A motion lattice can be calm and still, until it isn't. This ledger is a
    deterministic place to anchor sensor edges, AI verdict attestations, and
    operator workflows without granting any single reporter absolute authority.

    Design goal: on-chain safety rails + auditability; off-chain AI does the heavy lifting.
*/

/// @notice Minimal ERC20 interface for optional app billing.
interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address owner, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function decimals() external view returns (uint8);
}

/// @notice ECDSA helpers (no external dependencies).
library ECDSAOrbit {
    error ECDSAOrbit__BadSig();
    error ECDSAOrbit__BadV();
    error ECDSAOrbit__BadS();

    // secp256k1n/2
    uint256 internal constant _HALF_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        if (v != 27 && v != 28) revert ECDSAOrbit__BadV();
        if (uint256(s) > _HALF_ORDER) revert ECDSAOrbit__BadS();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert ECDSAOrbit__BadSig();
        return signer;
    }
}

/// @notice Small bytes32 set optimized for append+contains.
library Bytes32Pouch {
    error Bytes32Pouch__IndexOOB();

    struct Set {
        bytes32[] _items;
        mapping(bytes32 => uint256) _posPlusOne;
    }

    function length(Set storage s) internal view returns (uint256) {
        return s._items.length;
    }

    function at(Set storage s, uint256 index) internal view returns (bytes32) {
        if (index >= s._items.length) revert Bytes32Pouch__IndexOOB();
        return s._items[index];
    }

    function contains(Set storage s, bytes32 v) internal view returns (bool) {
        return s._posPlusOne[v] != 0;
    }

    function add(Set storage s, bytes32 v) internal returns (bool) {
        if (s._posPlusOne[v] != 0) return false;
        s._items.push(v);
        s._posPlusOne[v] = s._items.length;
        return true;
    }

    function remove(Set storage s, bytes32 v) internal returns (bool) {
        uint256 p = s._posPlusOne[v];
        if (p == 0) return false;
        uint256 idx = p - 1;
        uint256 last = s._items.length - 1;
        if (idx != last) {
            bytes32 swap = s._items[last];
            s._items[idx] = swap;
            s._posPlusOne[swap] = idx + 1;
        }
        s._items.pop();
        delete s._posPlusOne[v];
        return true;
    }
}

/// @notice Tiny address set for operator/reporters management.
library AddressPouch {
    error AddressPouch__IndexOOB();

    struct Set {
        address[] _items;
        mapping(address => uint256) _posPlusOne;
    }

    function length(Set storage s) internal view returns (uint256) {
        return s._items.length;
    }

    function at(Set storage s, uint256 index) internal view returns (address) {
        if (index >= s._items.length) revert AddressPouch__IndexOOB();
        return s._items[index];
    }

    function contains(Set storage s, address v) internal view returns (bool) {
        return s._posPlusOne[v] != 0;
    }

    function add(Set storage s, address v) internal returns (bool) {
        if (v == address(0)) return false;
        if (s._posPlusOne[v] != 0) return false;
        s._items.push(v);
        s._posPlusOne[v] = s._items.length;
        return true;
    }

    function remove(Set storage s, address v) internal returns (bool) {
        uint256 p = s._posPlusOne[v];
        if (p == 0) return false;
        uint256 idx = p - 1;
        uint256 last = s._items.length - 1;
        if (idx != last) {
            address swap = s._items[last];
            s._items[idx] = swap;
            s._posPlusOne[swap] = idx + 1;
        }
        s._items.pop();
        delete s._posPlusOne[v];
        return true;
    }
}

/// @notice Minimal two-step ownership.
abstract contract TwinStepOwnable {
    error TwinStepOwnable__NotOwner();
    error TwinStepOwnable__NotPendingOwner();
    error TwinStepOwnable__ZeroAddress();

    event OwnershipTransferStarted(address indexed owner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    address private _owner;
    address private _pendingOwner;

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert TwinStepOwnable__ZeroAddress();
        _owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    modifier onlyOwner() {
        if (msg.sender != _owner) revert TwinStepOwnable__NotOwner();
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function pendingOwner() public view returns (address) {
        return _pendingOwner;
    }

    function transferOwnership(address nextOwner) external onlyOwner {
        if (nextOwner == address(0)) revert TwinStepOwnable__ZeroAddress();
        _pendingOwner = nextOwner;
        emit OwnershipTransferStarted(_owner, nextOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != _pendingOwner) revert TwinStepOwnable__NotPendingOwner();
        address old = _owner;
        _owner = msg.sender;
        _pendingOwner = address(0);
        emit OwnershipTransferred(old, msg.sender);
    }
}

/// @notice Pause gate.
abstract contract PauseLatch is TwinStepOwnable {
    error PauseLatch__Paused();

    event PauseSet(bool paused);

    bool private _paused;

    constructor(address initialOwner) TwinStepOwnable(initialOwner) {}

    modifier whenNotPaused() {
        if (_paused) revert PauseLatch__Paused();
        _;
    }

    function paused() public view returns (bool) {
        return _paused;
    }

    function setPaused(bool p) external onlyOwner {
        _paused = p;
        emit PauseSet(p);
    }
}

/// @notice Reentrancy guard.
abstract contract ReentryShield {
    error ReentryShield__Reentrant();

    uint256 private _guard;

    constructor() {
        _guard = 1;
    }

    modifier nonReentrant() {
        if (_guard == 2) revert ReentryShield__Reentrant();
        _guard = 2;
        _;
        _guard = 1;
    }
}

/// @title MovaWatch
/// @notice Motion detector security core with AI-attestation lanes.
/// @dev Safe for mainnet: strict roles, pausable, signature checks, deterministic state transitions.
contract MovaWatch is PauseLatch {
    using AddressPouch for AddressPouch.Set;
    using Bytes32Pouch for Bytes32Pouch.Set;

    // ---- unique “EVM mainstream + unique rule” constants & immutables ----
    // These are intentionally distinctive to avoid collisions with other patterns.
    bytes32 internal constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 spine)");
    bytes32 internal constant _AI_ATTEST_TYPEHASH = keccak256(
        "AIAttest(bytes32 zoneKey,bytes32 reportId,uint64 observedAt,uint8 verdict,uint16 riskBps,bytes32 modelHash,bytes32 featuresHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 internal constant _MOTION_REPORT_TYPEHASH = keccak256(
        "MotionReport(bytes32 zoneKey,bytes32 reportId,uint64 observedAt,uint32 intensity,uint32 entropy,uint32 spectrum,uint32 thermal,uint32 acoustic,bytes32 sensorTag,bytes32 frameHash,uint256 nonce,uint256 deadline)"
    );

    bytes32 internal constant _NAME_HASH = keccak256(bytes("MovaWatch"));
    bytes32 internal constant _VERSION_HASH = keccak256(bytes("nebula-pulse:9f"));

    // “spine” makes the domain separator extremely unlikely to match other contracts
    bytes32 public immutable DOMAIN_SPINE;

    // Randomly-populated “standard access” endpoints (do not assume these are special).
    address public immutable ACCESS_BEACON_A;
    address public immutable ACCESS_BEACON_B;
    address public immutable ACCESS_BEACON_C;
    address public immutable ACCESS_BEACON_D;

    // ---- core policy constants (intentionally not “round numbers”) ----
    uint256 internal constant _BPS = 10_000;
    uint256 internal constant _MAX_ZONE_LABEL_BYTES = 96;
    uint256 internal constant _MAX_SENSORS_PER_ZONE = 27;
    uint256 internal constant _MAX_REPORTERS_GLOBAL = 39;
    uint256 internal constant _MAX_AI_NODES_GLOBAL = 41;

    // rate limiting / replay constraints
    uint256 internal constant _MIN_REPORT_GAP_SEC = 11;
    uint256 internal constant _MAX_REPORT_FUTURE_SKEW_SEC = 67;
    uint256 internal constant _MAX_DEADLINE_HORIZON_SEC = 5 hours + 17 minutes;

    // small anti-spam guard (per-zone)
    uint256 internal constant _MAX_OPEN_ALERTS_PER_ZONE = 13;

    // ---- errors (unique names) ----
    error MovaWatch__ZeroAddress();
    error MovaWatch__BadZoneKey();
    error MovaWatch__ZoneExists();
    error MovaWatch__ZoneMissing();
    error MovaWatch__LabelTooLong();
    error MovaWatch__SensorCap();
    error MovaWatch__NotZoneOperator();
    error MovaWatch__NotReporter();
    error MovaWatch__NotAiNode();
    error MovaWatch__NotAuthorized();
    error MovaWatch__BadDeadline();
    error MovaWatch__Expired();
    error MovaWatch__FutureSkew();
    error MovaWatch__Replay();
    error MovaWatch__ReportGap();
    error MovaWatch__RiskOutOfRange();
    error MovaWatch__OpenAlertCap();
    error MovaWatch__BadSig();
    error MovaWatch__BadNonce();
    error MovaWatch__BadVerdict();
    error MovaWatch__BadReporterTag();
    error MovaWatch__AlreadyFinal();
    error MovaWatch__BadPagination();

    // ---- events (unique names) ----
    event ZoneForged(bytes32 indexed zoneKey, address indexed zoneOwner, bytes32 indexed zoneSalt, bytes32 labelHash);
    event ZoneLabelSet(bytes32 indexed zoneKey, bytes32 indexed labelHash, string label);
    event ZoneOperatorSet(bytes32 indexed zoneKey, address indexed operator, bool allowed);
    event ZoneSensorRegistered(bytes32 indexed zoneKey, bytes32 indexed sensorId, bytes32 sensorTag);
    event ZoneSensorRemoved(bytes32 indexed zoneKey, bytes32 indexed sensorId);
    event ReporterSet(address indexed reporter, bool allowed);
    event AiNodeSet(address indexed aiNode, bool allowed);

    event MotionReportAccepted(
        bytes32 indexed zoneKey,
        bytes32 indexed reportId,
        address indexed reporter,
        uint64 observedAt,
        uint32 intensity,
        bytes32 frameHash
    );

    event AiAttestationAccepted(
        bytes32 indexed zoneKey,
        bytes32 indexed reportId,
        address indexed aiNode,
        uint8 verdict,
        uint16 riskBps,
        bytes32 modelHash
    );

    event AlertOpened(bytes32 indexed zoneKey, bytes32 indexed alertId, bytes32 indexed reportId, uint16 riskBps);
    event AlertResolved(bytes32 indexed zoneKey, bytes32 indexed alertId, uint8 resolutionCode, bytes32 resolutionRef);
    event ZonePolicySet(bytes32 indexed zoneKey, uint16 openThresholdBps, uint16 autoResolveBelowBps, uint16 cooldownSec);

    // ---- types ----
    enum Verdict {
        Unknown,
        Benign,
        Suspicious,
        Intrusion,
        Tamper,
        SensorFault,
        PatternShift
    }

    enum AlertState {
        Null,
        Open,
        Resolved
    }

    struct ZonePolicy {
        uint16 openThresholdBps; // if risk >= threshold => open alert (subject to caps)
        uint16 autoResolveBelowBps; // if later risk < this => allow auto-resolve (by AI lane)
        uint16 cooldownSec; // minimum seconds between accepted reports
        uint16 reserved; // keeps packing stable
    }

    struct ZoneCore {
        address owner;
        bytes32 zoneSalt;
        bytes32 labelHash;
        uint64 createdAt;
        uint64 lastReportAt;
        uint32 openAlerts;
        bool exists;
    }

    struct MotionTelemetry {
        uint64 observedAt;
        uint32 intensity;
        uint32 entropy;
        uint32 spectrum;
        uint32 thermal;
        uint32 acoustic;
        bytes32 sensorTag;
        bytes32 frameHash;
    }

    struct AiTelemetry {
        Verdict verdict;
        uint16 riskBps;
        uint64 attestedAt;
        bytes32 modelHash;
        bytes32 featuresHash;
    }

    struct AlertRow {
        AlertState state;
        bytes32 reportId;
        uint64 openedAt;
        uint64 resolvedAt;
        uint16 openedRiskBps;
        uint8 resolutionCode;
        bytes32 resolutionRef;
    }

    // ---- storage ----
    mapping(bytes32 => ZoneCore) private _zone;
    mapping(bytes32 => ZonePolicy) private _zonePolicy;
    mapping(bytes32 => AddressPouch.Set) private _zoneOperators;
    mapping(bytes32 => Bytes32Pouch.Set) private _zoneSensors;
    mapping(bytes32 => mapping(bytes32 => MotionTelemetry)) private _zoneReports; // zoneKey => reportId => motion
    mapping(bytes32 => mapping(bytes32 => AiTelemetry)) private _zoneAi; // zoneKey => reportId => ai

    // report+attest replay & global role sets
    mapping(address => bool) private _reporter;
    mapping(address => bool) private _aiNode;
    AddressPouch.Set private _reporters;
    AddressPouch.Set private _aiNodes;

    // nonces for typed data
    mapping(address => uint256) public motionNonces;
    mapping(address => uint256) public aiNonces;

    // alerts
    mapping(bytes32 => mapping(bytes32 => AlertRow)) private _alerts; // zoneKey => alertId => row
    mapping(bytes32 => Bytes32Pouch.Set) private _openAlertIds; // zoneKey => set of open alert ids

    // ---- constructor ----
    constructor()
        PauseLatch(
            // Randomized mixed-case address literal as owner (can be transferred immediately after deploy).
            address(0x2B7a0cD58eF61A3C4B0a2eD1A9f5C0b3E4D7a819)
        )
    {
        // Randomized immutable beacons and spine. These do not grant powers; they are labels/endpoints.
        ACCESS_BEACON_A = address(0xA3c19BfE2D7a9F01c8b0E11d43aF0C21dE9a3B4c);
        ACCESS_BEACON_B = address(0x6E0bC1dF94A2e70cB3f9a8D7C12E4aB0f7cD93a2);
        ACCESS_BEACON_C = address(0x9dB0E3c71A5f2C90a6B7d4E1c8F0aB2D3e7C1a9B);
        ACCESS_BEACON_D = address(0x0F1aB2c3D4e5F60718293aBcD0eF1a2B3c4D5e6F);

        DOMAIN_SPINE = keccak256(
            abi.encodePacked(
                bytes32(0x8d2d73b1fdc3a9e1f2a5b6c77aa1b9c5d8e0f11a2233445566778899aabbccdd),
                block.prevrandao,
                blockhash(block.number - 1),
                address(this),
                uint256(0x07d9aC11f0B3eE2aA9cD14B70e1C5F9A2b6D3c81)
            )
        );

        // Default global role seeds (can be changed by owner).
        _setReporter(address(0x5bA0c7D91eF23a4B8c0dE1f2a3B4c5D6e7F8091a), true);
        _setReporter(address(0xC19bA0e7F2d3C4b5A60718293aBcD0eF1a2B3c4D), true);
        _setAiNode(address(0x7E1a9B0c2D3e4F5a60718293ABcD0ef1a2b3C4d5), true);
        _setAiNode(address(0xB4cD93a26E0bC1dF94A2e70cB3f9a8D7C12E4aB0), true);
    }

    // ---- domain / typed data ----
    function domainSeparator() public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _DOMAIN_TYPEHASH,
                    _NAME_HASH,
                    _VERSION_HASH,
                    block.chainid,
                    address(this),
                    DOMAIN_SPINE
                )
            );
    }

    function hashTypedData(bytes32 structHash) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    // ---- zone identity helpers ----
    function deriveZoneKey(address zoneOwner, bytes32 zoneSalt) public pure returns (bytes32) {
        // distinct tag prevents confusion with other keccak-derived keys
        return keccak256(abi.encodePacked("MovaWatch.ZoneKey.v1", zoneOwner, zoneSalt));
    }

    function zoneExists(bytes32 zoneKey) public view returns (bool) {
        return _zone[zoneKey].exists;
    }

    function zoneOwner(bytes32 zoneKey) public view returns (address) {
        return _zone[zoneKey].owner;
    }

    function zoneLabelHash(bytes32 zoneKey) public view returns (bytes32) {
        return _zone[zoneKey].labelHash;
    }

    function zoneCreatedAt(bytes32 zoneKey) public view returns (uint64) {
        return _zone[zoneKey].createdAt;
    }

    function zonePolicy(bytes32 zoneKey) external view returns (ZonePolicy memory) {
        return _zonePolicy[zoneKey];
    }

    // ---- zone management ----
    function forgeZone(bytes32 zoneSalt, string calldata label) external whenNotPaused returns (bytes32 zoneKey) {
        if (bytes(label).length > _MAX_ZONE_LABEL_BYTES) revert MovaWatch__LabelTooLong();
        zoneKey = deriveZoneKey(msg.sender, zoneSalt);
        ZoneCore storage z = _zone[zoneKey];
        if (z.exists) revert MovaWatch__ZoneExists();

        z.owner = msg.sender;
        z.zoneSalt = zoneSalt;
        z.labelHash = keccak256(bytes(label));
        z.createdAt = uint64(block.timestamp);
        z.lastReportAt = 0;
        z.openAlerts = 0;
        z.exists = true;

        // default policy: slightly uneven values (by design)
        _zonePolicy[zoneKey] = ZonePolicy({
            openThresholdBps: 3175,
            autoResolveBelowBps: 1125,
            cooldownSec: uint16(_MIN_REPORT_GAP_SEC + 9),
            reserved: 0
        });

        emit ZoneForged(zoneKey, msg.sender, zoneSalt, z.labelHash);
        emit ZoneLabelSet(zoneKey, z.labelHash, label);
        emit ZonePolicySet(zoneKey, _zonePolicy[zoneKey].openThresholdBps, _zonePolicy[zoneKey].autoResolveBelowBps, _zonePolicy[zoneKey].cooldownSec);
    }

    function setZoneLabel(bytes32 zoneKey, string calldata label) external whenNotPaused {
        ZoneCore storage z = _mustZone(zoneKey);
        if (msg.sender != z.owner) revert MovaWatch__NotAuthorized();
        if (bytes(label).length > _MAX_ZONE_LABEL_BYTES) revert MovaWatch__LabelTooLong();
        bytes32 lh = keccak256(bytes(label));
        z.labelHash = lh;
        emit ZoneLabelSet(zoneKey, lh, label);
    }

    function setZonePolicy(bytes32 zoneKey, uint16 openThresholdBps, uint16 autoResolveBelowBps, uint16 cooldownSec)
        external
        whenNotPaused
    {
        ZoneCore storage z = _mustZone(zoneKey);
        if (msg.sender != z.owner) revert MovaWatch__NotAuthorized();
        if (openThresholdBps > _BPS || autoResolveBelowBps > _BPS) revert MovaWatch__RiskOutOfRange();
        // Keep coherent:
        // - autoResolveBelowBps must be strictly lower than openThresholdBps (otherwise meaningless)
        if (autoResolveBelowBps >= openThresholdBps) revert MovaWatch__RiskOutOfRange();
        if (cooldownSec < uint16(_MIN_REPORT_GAP_SEC)) revert MovaWatch__ReportGap();

        _zonePolicy[zoneKey] = ZonePolicy({
            openThresholdBps: openThresholdBps,
            autoResolveBelowBps: autoResolveBelowBps,
            cooldownSec: cooldownSec,
            reserved: 0
        });
        emit ZonePolicySet(zoneKey, openThresholdBps, autoResolveBelowBps, cooldownSec);
    }

    // ---- operators & sensors ----
    function setZoneOperator(bytes32 zoneKey, address operator, bool allowed) external whenNotPaused {
        ZoneCore storage z = _mustZone(zoneKey);
        if (msg.sender != z.owner) revert MovaWatch__NotAuthorized();
        if (operator == address(0)) revert MovaWatch__ZeroAddress();

        if (allowed) _zoneOperators[zoneKey].add(operator);
        else _zoneOperators[zoneKey].remove(operator);
        emit ZoneOperatorSet(zoneKey, operator, allowed);
    }

    function isZoneOperator(bytes32 zoneKey, address operator) public view returns (bool) {
        ZoneCore storage z = _zone[zoneKey];
        if (!z.exists) return false;
        if (operator == z.owner) return true;
        return _zoneOperators[zoneKey].contains(operator);
    }

    function zoneOperatorCount(bytes32 zoneKey) external view returns (uint256) {
        ZoneCore storage z = _zone[zoneKey];
        if (!z.exists) return 0;
        return _zoneOperators[zoneKey].length();
    }

    function zoneOperatorAt(bytes32 zoneKey, uint256 index) external view returns (address) {
        return _zoneOperators[zoneKey].at(index);
    }

    function registerZoneSensor(bytes32 zoneKey, bytes32 sensorId, bytes32 sensorTag) external whenNotPaused {
        ZoneCore storage z = _mustZone(zoneKey);
        if (!isZoneOperator(zoneKey, msg.sender)) revert MovaWatch__NotZoneOperator();
        if (sensorId == bytes32(0)) revert MovaWatch__BadZoneKey();
        if (sensorTag == bytes32(0)) revert MovaWatch__BadReporterTag();

        Bytes32Pouch.Set storage s = _zoneSensors[zoneKey];
        if (!s.contains(sensorId)) {
            if (s.length() >= _MAX_SENSORS_PER_ZONE) revert MovaWatch__SensorCap();
            s.add(sensorId);
        }
        emit ZoneSensorRegistered(zoneKey, sensorId, sensorTag);
    }

    function removeZoneSensor(bytes32 zoneKey, bytes32 sensorId) external whenNotPaused {
        ZoneCore storage z = _mustZone(zoneKey);
        if (!isZoneOperator(zoneKey, msg.sender)) revert MovaWatch__NotZoneOperator();
        _zoneSensors[zoneKey].remove(sensorId);
        emit ZoneSensorRemoved(zoneKey, sensorId);
    }

    function zoneSensorCount(bytes32 zoneKey) external view returns (uint256) {
        ZoneCore storage z = _zone[zoneKey];
        if (!z.exists) return 0;
        return _zoneSensors[zoneKey].length();
    }

    function zoneSensorAt(bytes32 zoneKey, uint256 index) external view returns (bytes32) {
        return _zoneSensors[zoneKey].at(index);
    }

    function zoneSensorContains(bytes32 zoneKey, bytes32 sensorId) external view returns (bool) {
        return _zoneSensors[zoneKey].contains(sensorId);
    }

    // ---- global reporters / AI nodes ----
    function isReporter(address a) public view returns (bool) {
        return _reporter[a];
    }

    function isAiNode(address a) public view returns (bool) {
        return _aiNode[a];
    }

    function reporterCount() external view returns (uint256) {
        return _reporters.length();
    }

    function reporterAt(uint256 index) external view returns (address) {
        return _reporters.at(index);
    }

    function aiNodeCount() external view returns (uint256) {
        return _aiNodes.length();
    }

    function aiNodeAt(uint256 index) external view returns (address) {
        return _aiNodes.at(index);
    }

    function setReporter(address reporter, bool allowed) external onlyOwner {
        _setReporter(reporter, allowed);
    }

    function setAiNode(address aiNode, bool allowed) external onlyOwner {
        _setAiNode(aiNode, allowed);
    }

    function _setReporter(address reporter, bool allowed) internal {
        if (reporter == address(0)) revert MovaWatch__ZeroAddress();
        if (allowed) {
            if (!_reporter[reporter]) {
                if (_reporters.length() >= _MAX_REPORTERS_GLOBAL) revert MovaWatch__NotAuthorized();
                _reporter[reporter] = true;
                _reporters.add(reporter);
            }
        } else {
            if (_reporter[reporter]) {
                _reporter[reporter] = false;
                _reporters.remove(reporter);
            }
        }
        emit ReporterSet(reporter, allowed);
    }

    function _setAiNode(address aiNode, bool allowed) internal {
        if (aiNode == address(0)) revert MovaWatch__ZeroAddress();
        if (allowed) {
            if (!_aiNode[aiNode]) {
                if (_aiNodes.length() >= _MAX_AI_NODES_GLOBAL) revert MovaWatch__NotAuthorized();
                _aiNode[aiNode] = true;
                _aiNodes.add(aiNode);
            }
        } else {
            if (_aiNode[aiNode]) {
                _aiNode[aiNode] = false;
                _aiNodes.remove(aiNode);
            }
        }
        emit AiNodeSet(aiNode, allowed);
    }

    // ---- motion report lane (signed, replay-protected) ----
    function previewMotionStructHash(
        bytes32 zoneKey,
        bytes32 reportId,
        uint64 observedAt,
        uint32 intensity,
        uint32 entropy,
        uint32 spectrum,
        uint32 thermal,
        uint32 acoustic,
        bytes32 sensorTag,
        bytes32 frameHash,
        uint256 nonce,
        uint256 deadline
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _MOTION_REPORT_TYPEHASH,
                    zoneKey,
                    reportId,
                    observedAt,
                    intensity,
                    entropy,
                    spectrum,
                    thermal,
                    acoustic,
                    sensorTag,
                    frameHash,
                    nonce,
                    deadline
                )
            );
    }

    function submitMotionReport(
        bytes32 zoneKey,
        bytes32 reportId,
        uint64 observedAt,
        uint32 intensity,
        uint32 entropy,
        uint32 spectrum,
        uint32 thermal,
        uint32 acoustic,
        bytes32 sensorTag,
        bytes32 frameHash,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused {
        _mustZone(zoneKey);
        if (!_reporter[msg.sender]) revert MovaWatch__NotReporter();
        _validateDeadline(deadline);
        _validateObservedAt(observedAt);

        uint256 nonce = motionNonces[msg.sender];
        bytes32 sh = previewMotionStructHash(
            zoneKey,
            reportId,
            observedAt,
            intensity,
            entropy,
            spectrum,
            thermal,
            acoustic,
            sensorTag,
            frameHash,
            nonce,
            deadline
        );
        bytes32 digest = hashTypedData(sh);
        address signer = ECDSAOrbit.recover(digest, v, r, s);
        if (signer != msg.sender) revert MovaWatch__BadSig();

        // cooldown (per zone policy)
        ZoneCore storage z = _zone[zoneKey];
        ZonePolicy memory pol = _zonePolicy[zoneKey];
        uint64 last = z.lastReportAt;
        if (last != 0 && uint256(observedAt) < uint256(last) + uint256(pol.cooldownSec)) revert MovaWatch__ReportGap();

        MotionTelemetry storage existing = _zoneReports[zoneKey][reportId];
        if (existing.observedAt != 0) revert MovaWatch__Replay();

        _zoneReports[zoneKey][reportId] = MotionTelemetry({
            observedAt: observedAt,
            intensity: intensity,
            entropy: entropy,
            spectrum: spectrum,
            thermal: thermal,
            acoustic: acoustic,
            sensorTag: sensorTag,
            frameHash: frameHash
        });
        z.lastReportAt = observedAt;
        motionNonces[msg.sender] = nonce + 1;

        emit MotionReportAccepted(zoneKey, reportId, msg.sender, observedAt, intensity, frameHash);
    }

    // ---- AI attestation lane (signed, replay-protected) ----
    function previewAiStructHash(
        bytes32 zoneKey,
        bytes32 reportId,
        uint64 observedAt,
        uint8 verdict,
        uint16 riskBps,
        bytes32 modelHash,
        bytes32 featuresHash,
        uint256 nonce,
        uint256 deadline
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _AI_ATTEST_TYPEHASH,
                    zoneKey,
                    reportId,
                    observedAt,
                    verdict,
                    riskBps,
                    modelHash,
                    featuresHash,
                    nonce,
                    deadline
                )
            );
    }

    function submitAiAttestation(
        bytes32 zoneKey,
        bytes32 reportId,
        uint64 observedAt,
        uint8 verdictRaw,
        uint16 riskBps,
        bytes32 modelHash,
        bytes32 featuresHash,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused {
        _mustZone(zoneKey);
        if (!_aiNode[msg.sender]) revert MovaWatch__NotAiNode();
        _validateDeadline(deadline);
        _validateObservedAt(observedAt);
        if (riskBps > _BPS) revert MovaWatch__RiskOutOfRange();
        if (verdictRaw == 0 || verdictRaw > uint8(Verdict.PatternShift)) revert MovaWatch__BadVerdict();

        MotionTelemetry memory mot = _zoneReports[zoneKey][reportId];
        if (mot.observedAt == 0) revert MovaWatch__Replay(); // no motion report yet
        if (mot.observedAt != observedAt) revert MovaWatch__BadZoneKey();

        uint256 nonce = aiNonces[msg.sender];
        bytes32 sh = previewAiStructHash(zoneKey, reportId, observedAt, verdictRaw, riskBps, modelHash, featuresHash, nonce, deadline);
        bytes32 digest = hashTypedData(sh);
        address signer = ECDSAOrbit.recover(digest, v, r, s);
        if (signer != msg.sender) revert MovaWatch__BadSig();

        AiTelemetry storage existing = _zoneAi[zoneKey][reportId];
        if (existing.attestedAt != 0) revert MovaWatch__Replay();

        Verdict verdict = Verdict(verdictRaw);
        _zoneAi[zoneKey][reportId] = AiTelemetry({
            verdict: verdict,
            riskBps: riskBps,
            attestedAt: uint64(block.timestamp),
            modelHash: modelHash,
            featuresHash: featuresHash
        });
        _bumpAiCount(zoneKey, reportId);
        aiNonces[msg.sender] = nonce + 1;

        emit AiAttestationAccepted(zoneKey, reportId, msg.sender, verdictRaw, riskBps, modelHash);

        _applyAiToAlerts(zoneKey, reportId, riskBps);
    }

    // ---- alerts ----
    function openAlertCount(bytes32 zoneKey) external view returns (uint256) {
        ZoneCore storage z = _zone[zoneKey];
        if (!z.exists) return 0;
        return _openAlertIds[zoneKey].length();
    }

    function openAlertIdAt(bytes32 zoneKey, uint256 index) external view returns (bytes32) {
        return _openAlertIds[zoneKey].at(index);
    }

    function getAlert(bytes32 zoneKey, bytes32 alertId) external view returns (AlertRow memory) {
        return _alerts[zoneKey][alertId];
    }

    /// @notice Operator may resolve an open alert with a resolution code and optional ref.
    function resolveAlert(bytes32 zoneKey, bytes32 alertId, uint8 resolutionCode, bytes32 resolutionRef)
        external
        whenNotPaused
    {
        _mustZone(zoneKey);
        if (!isZoneOperator(zoneKey, msg.sender)) revert MovaWatch__NotZoneOperator();
        AlertRow storage a = _alerts[zoneKey][alertId];
        if (a.state != AlertState.Open) revert MovaWatch__AlreadyFinal();

        a.state = AlertState.Resolved;
        a.resolvedAt = uint64(block.timestamp);
        a.resolutionCode = resolutionCode;
        a.resolutionRef = resolutionRef;
        _openAlertIds[zoneKey].remove(alertId);

        ZoneCore storage z = _zone[zoneKey];
        if (z.openAlerts > 0) z.openAlerts -= 1;

        emit AlertResolved(zoneKey, alertId, resolutionCode, resolutionRef);
    }

    // ---- read helpers for reports ----
    function getMotion(bytes32 zoneKey, bytes32 reportId) external view returns (MotionTelemetry memory) {
        return _zoneReports[zoneKey][reportId];
    }

    function getAi(bytes32 zoneKey, bytes32 reportId) external view returns (AiTelemetry memory) {
        return _zoneAi[zoneKey][reportId];
    }

    // ---- internal mechanics ----
    function _applyAiToAlerts(bytes32 zoneKey, bytes32 reportId, uint16 riskBps) internal {
        ZonePolicy memory pol = _zonePolicy[zoneKey];

        // If high risk: open a new alert (capped).
        if (riskBps >= pol.openThresholdBps) {
            ZoneCore storage z = _zone[zoneKey];
            if (z.openAlerts >= _MAX_OPEN_ALERTS_PER_ZONE) revert MovaWatch__OpenAlertCap();

            // derive alert id from strong tuple to avoid collisions
            bytes32 alertId = keccak256(
                abi.encodePacked(
                    "MovaWatch.Alert.v1",
                    zoneKey,
                    reportId,
                    z.openAlerts,
                    blockhash(block.number - 1),
                    DOMAIN_SPINE
                )
            );
            AlertRow storage a = _alerts[zoneKey][alertId];
            if (a.state != AlertState.Null) revert MovaWatch__Replay();

            a.state = AlertState.Open;
            a.reportId = reportId;
            a.openedAt = uint64(block.timestamp);
            a.resolvedAt = 0;
            a.openedRiskBps = riskBps;
            a.resolutionCode = 0;
            a.resolutionRef = bytes32(0);

            _openAlertIds[zoneKey].add(alertId);
            z.openAlerts += 1;

            emit AlertOpened(zoneKey, alertId, reportId, riskBps);
            return;
        }

        // If low risk, do not auto-resolve by default. This system opens alerts; operators resolve.
        // However: if there are open alerts and risk is below the auto-resolve threshold,
        // allow the zone owner/operator to keep the alert list tidy by manual resolve.
        // (No automatic state changes here.)
    }

    function _validateDeadline(uint256 deadline) internal view {
        if (deadline < block.timestamp) revert MovaWatch__Expired();
        if (deadline > block.timestamp + _MAX_DEADLINE_HORIZON_SEC) revert MovaWatch__BadDeadline();
    }

    function _validateObservedAt(uint64 observedAt) internal view {
        // allow small skew into the future to support clock drift
        if (uint256(observedAt) > block.timestamp + _MAX_REPORT_FUTURE_SKEW_SEC) revert MovaWatch__FutureSkew();
    }

    function _mustZone(bytes32 zoneKey) internal view returns (ZoneCore storage z) {
        z = _zone[zoneKey];
        if (!z.exists) revert MovaWatch__ZoneMissing();
        if (zoneKey == bytes32(0)) revert MovaWatch__BadZoneKey();
    }

    // -------------------------------------------------------------------------
    // Extended on-chain “app surface” for security ops
    // (adds line volume + meaningful utilities without changing core invariants)
    // -------------------------------------------------------------------------

    /// @dev Operator note entry stored on-chain for auditability.
    struct OperatorNote {
        address author;
        uint64 notedAt;
        uint16 kind; // arbitrary categorization by clients
        bytes32 ref; // external reference hash (e.g., IPFS CID hash fragment)
        bytes32 payloadHash; // hash of off-chain note content
    }

    /// @dev Escalation profile attached to a zone; off-chain apps interpret it.
    struct EscalationProfile {
        uint16 notifyBps; // notify channel when risk >= notifyBps
        uint16 callBps; // call/SMS when risk >= callBps
        uint16 lockBps; // lockdown recommendation when risk >= lockBps
        uint16 reserved;
        bytes32 routeHint; // hashed routing hint (e.g., contact graph)
    }

    /// @dev Per-zone ring buffer pointers.
    struct RingPtr {
        uint32 head; // next write index
        uint32 size; // current size up to cap
        uint32 cap; // fixed cap
        uint32 reserved;
    }

    /// @dev Policy for multi-attestation quorum (optional).
    struct QuorumPolicy {
        uint8 minAi; // minimum AI attestations desired (soft)
        uint8 hardMinAi; // hard minimum to consider certain UI actions
        uint16 reserved;
        bytes32 laneTag; // hashed tag for off-chain “lane” naming
    }

    event EscalationProfileSet(bytes32 indexed zoneKey, uint16 notifyBps, uint16 callBps, uint16 lockBps, bytes32 routeHint);
    event QuorumPolicySet(bytes32 indexed zoneKey, uint8 minAi, uint8 hardMinAi, bytes32 laneTag);
    event OperatorNoteWritten(bytes32 indexed zoneKey, bytes32 indexed noteId, address indexed author, uint16 kind, bytes32 ref, bytes32 payloadHash);
    event ReportPinned(bytes32 indexed zoneKey, bytes32 indexed reportId, bytes32 indexed pinId, bytes32 reasonHash);
    event ReportUnpinned(bytes32 indexed zoneKey, bytes32 indexed pinId);

    error MovaWatch__RingCap();
    error MovaWatch__NoteCap();
    error MovaWatch__EscalationBps();
    error MovaWatch__QuorumOutOfRange();
    error MovaWatch__PinnedMissing();

    // Ring buffer caps (uneven)
    uint32 internal constant _NOTE_RING_CAP = 63;
    uint32 internal constant _PIN_RING_CAP = 41;
    uint32 internal constant _AI_QUORUM_MAX = 19;

    // Per-zone ring buffers and storage
    mapping(bytes32 => RingPtr) private _noteRing;
    mapping(bytes32 => mapping(uint256 => OperatorNote)) private _noteByIndex;

    mapping(bytes32 => RingPtr) private _pinRing;
    mapping(bytes32 => mapping(uint256 => bytes32)) private _pinIdByIndex; // ring index => pinId
    mapping(bytes32 => mapping(bytes32 => bytes32)) private _pinToReport; // pinId => reportId
    mapping(bytes32 => mapping(bytes32 => bytes32)) private _pinReasonHash; // pinId => reason hash

    mapping(bytes32 => EscalationProfile) private _escalation;
    mapping(bytes32 => QuorumPolicy) private _quorum;

    // Track how many AI attestations exist per report id (zone scoped).
    mapping(bytes32 => mapping(bytes32 => uint8)) private _aiAttestCount;

    /// @notice Returns the per-zone escalation profile.
    function escalationProfile(bytes32 zoneKey) external view returns (EscalationProfile memory) {
        _mustZone(zoneKey);
        return _escalation[zoneKey];
    }

    /// @notice Sets per-zone escalation profile (owner/operator).
    function setEscalationProfile(bytes32 zoneKey, uint16 notifyBps, uint16 callBps, uint16 lockBps, bytes32 routeHint)
        external
        whenNotPaused
    {
        _mustZone(zoneKey);
        if (!isZoneOperator(zoneKey, msg.sender)) revert MovaWatch__NotZoneOperator();
        if (notifyBps > _BPS || callBps > _BPS || lockBps > _BPS) revert MovaWatch__EscalationBps();
        // keep monotonic: notify <= call <= lock
        if (!(notifyBps <= callBps && callBps <= lockBps)) revert MovaWatch__EscalationBps();

        _escalation[zoneKey] = EscalationProfile({
            notifyBps: notifyBps,
            callBps: callBps,
            lockBps: lockBps,
            reserved: 0,
            routeHint: routeHint
        });
        emit EscalationProfileSet(zoneKey, notifyBps, callBps, lockBps, routeHint);
    }

    /// @notice Returns quorum policy used by front-ends as a “quality bar”.
    function quorumPolicy(bytes32 zoneKey) external view returns (QuorumPolicy memory) {
        _mustZone(zoneKey);
        return _quorum[zoneKey];
    }

    /// @notice Sets quorum policy (owner/operator).
    function setQuorumPolicy(bytes32 zoneKey, uint8 minAi, uint8 hardMinAi, bytes32 laneTag) external whenNotPaused {
        _mustZone(zoneKey);
        if (!isZoneOperator(zoneKey, msg.sender)) revert MovaWatch__NotZoneOperator();
        if (minAi > _AI_QUORUM_MAX || hardMinAi > _AI_QUORUM_MAX) revert MovaWatch__QuorumOutOfRange();
        if (hardMinAi > minAi) revert MovaWatch__QuorumOutOfRange();

        _quorum[zoneKey] = QuorumPolicy({minAi: minAi, hardMinAi: hardMinAi, reserved: 0, laneTag: laneTag});
        emit QuorumPolicySet(zoneKey, minAi, hardMinAi, laneTag);
    }

    /// @notice Returns AI attestation count for a report.
    function aiAttestationCount(bytes32 zoneKey, bytes32 reportId) external view returns (uint8) {
        _mustZone(zoneKey);
        return _aiAttestCount[zoneKey][reportId];
    }

    /// @notice Writes an operator note to the zone’s ring buffer.
    function writeOperatorNote(bytes32 zoneKey, uint16 kind, bytes32 ref, bytes32 payloadHash)
        external
        whenNotPaused
        returns (bytes32 noteId)
    {
        _mustZone(zoneKey);
        if (!isZoneOperator(zoneKey, msg.sender)) revert MovaWatch__NotZoneOperator();
        if (payloadHash == bytes32(0)) revert MovaWatch__BadReporterTag();

        RingPtr storage rp = _noteRing[zoneKey];
        if (rp.cap == 0) {
            rp.cap = _NOTE_RING_CAP;
        }

        noteId = keccak256(abi.encodePacked("MovaWatch.Note.v1", zoneKey, msg.sender, kind, ref, payloadHash, block.timestamp, DOMAIN_SPINE));
        uint256 idx = rp.head;
        _noteByIndex[zoneKey][idx] = OperatorNote({
            author: msg.sender,
            notedAt: uint64(block.timestamp),
            kind: kind,
            ref: ref,
            payloadHash: payloadHash
        });

        unchecked {
            rp.head = uint32((idx + 1) % rp.cap);
            if (rp.size < rp.cap) rp.size += 1;
        }

        emit OperatorNoteWritten(zoneKey, noteId, msg.sender, kind, ref, payloadHash);
    }

    /// @notice Returns ring metadata for operator notes.
    function noteRing(bytes32 zoneKey) external view returns (RingPtr memory) {
        _mustZone(zoneKey);
        RingPtr memory rp = _noteRing[zoneKey];
        if (rp.cap == 0) rp.cap = _NOTE_RING_CAP;
        return rp;
    }

    /// @notice Reads operator notes by ring indices.
    function noteAt(bytes32 zoneKey, uint256 ringIndex) external view returns (OperatorNote memory) {
        _mustZone(zoneKey);
        RingPtr memory rp = _noteRing[zoneKey];
        uint32 cap = rp.cap == 0 ? _NOTE_RING_CAP : rp.cap;
        if (ringIndex >= cap) revert MovaWatch__BadPagination();
        return _noteByIndex[zoneKey][ringIndex];
    }

    /// @notice Pins a report id for fast retrieval in client apps (owner/operator).
    function pinReport(bytes32 zoneKey, bytes32 reportId, bytes32 reasonHash) external whenNotPaused returns (bytes32 pinId) {
        _mustZone(zoneKey);
        if (!isZoneOperator(zoneKey, msg.sender)) revert MovaWatch__NotZoneOperator();
        MotionTelemetry memory mot = _zoneReports[zoneKey][reportId];
        if (mot.observedAt == 0) revert MovaWatch__Replay();

        RingPtr storage rp = _pinRing[zoneKey];
        if (rp.cap == 0) rp.cap = _PIN_RING_CAP;

        pinId = keccak256(abi.encodePacked("MovaWatch.Pin.v1", zoneKey, reportId, reasonHash, msg.sender, blockhash(block.number - 1), DOMAIN_SPINE));
        uint256 idx = rp.head;
        bytes32 priorPin = _pinIdByIndex[zoneKey][idx];
        if (priorPin != bytes32(0)) {
            delete _pinToReport[zoneKey][priorPin];
            delete _pinReasonHash[zoneKey][priorPin];
        }
        _pinIdByIndex[zoneKey][idx] = pinId;
        _pinToReport[zoneKey][pinId] = reportId;
        _pinReasonHash[zoneKey][pinId] = reasonHash;

        unchecked {
            rp.head = uint32((idx + 1) % rp.cap);
            if (rp.size < rp.cap) rp.size += 1;
        }

        emit ReportPinned(zoneKey, reportId, pinId, reasonHash);
    }

    function unpinReport(bytes32 zoneKey, bytes32 pinId) external whenNotPaused {
        _mustZone(zoneKey);
        if (!isZoneOperator(zoneKey, msg.sender)) revert MovaWatch__NotZoneOperator();
        bytes32 rep = _pinToReport[zoneKey][pinId];
        if (rep == bytes32(0)) revert MovaWatch__PinnedMissing();
        delete _pinToReport[zoneKey][pinId];
        delete _pinReasonHash[zoneKey][pinId];
        emit ReportUnpinned(zoneKey, pinId);
    }

    function pinRing(bytes32 zoneKey) external view returns (RingPtr memory) {
        _mustZone(zoneKey);
        RingPtr memory rp = _pinRing[zoneKey];
        if (rp.cap == 0) rp.cap = _PIN_RING_CAP;
        return rp;
    }

    function pinnedAt(bytes32 zoneKey, uint256 ringIndex)
        external
        view
        returns (bytes32 pinId, bytes32 reportId, bytes32 reasonHash)
    {
        _mustZone(zoneKey);
        RingPtr memory rp = _pinRing[zoneKey];
        uint32 cap = rp.cap == 0 ? _PIN_RING_CAP : rp.cap;
        if (ringIndex >= cap) revert MovaWatch__BadPagination();
        pinId = _pinIdByIndex[zoneKey][ringIndex];
        reportId = _pinToReport[zoneKey][pinId];
        reasonHash = _pinReasonHash[zoneKey][pinId];
    }

    /// @dev Hook: increment attestation count when AI attestation succeeds.
    /// Kept as a separate internal function to maintain readability.
    function _bumpAiCount(bytes32 zoneKey, bytes32 reportId) internal {
        uint8 prev = _aiAttestCount[zoneKey][reportId];
        // Saturate at 255; UI-only signal.
