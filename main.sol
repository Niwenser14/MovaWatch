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
