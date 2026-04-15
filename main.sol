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
