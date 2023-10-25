
## Medium Findings

|    | Issue | Instances |
|----|-------|:---------:|
| [M-01] | Low Level Calls to Custom Addresses | 1 |
| [M-02] | Possible Vulnerability to Fee-On-Transfer Accounting Issues | 1 |
| [M-03] | Potential Gas Griefing Due to Non-Handling of Return Data in External Calls | 1 |

Total: 3 instances of 3 issues

## Low Findings

|    | Issue | Instances |
|----|-------|:---------:|
| [L-01] | State Address Changes Should Be a Two-Step Procedure | 1 |
| [L-02] | Consider to Use `SafeCast` for Casting | 2 |
| [L-03] | Missing Contract-Existence Checks Before Low-Level Calls | 1 |
| [L-04] | Using Draft Contract Imports | 2 |
| [L-05] | Risk of Revert from External Calls in Unbounded For-loops | 2 |
| [L-06] | Potential loss of precision in division operations | 2 |
| [L-07] | Missing `address(0)` Check in Constructor/Initializer | 10 |
| [L-08] | Function Parameters in Public Accessible Functions Need `address(0)` Check | 55 |
| [L-09] | Potential Re-org Attack Vector | 1 |
| [L-10] | Possible Revert ERC20 Transfers with Zero Value | 1 |
| [L-11] | Large Token Transfers Could Revert For Certain Tokens | 1 |
| [L-12] | Potential Unbounded Gas Consumption on External Calls | 1 |
| [L-13] | State variables are not limited to a reasonable range | 2 |
| [L-14] | Use two-step ownership transfers is import `Ownable2Step` | 1 |

Total: 96 instances of 16 issues

## Non-critical Findings

|    | Issue | Instances |
|----|-------|:---------:|
| [NC-01] | Use `delete` to clear variables instead of zero assignment | 2 |
| [NC-02] | Use `bytes.concat()` instead of `abi.encodePacked()` | 1 |
| [NC-03] | Constants on the right side of comparison statements | 12 |
| [NC-04] | Variable Names Not in mixedCase | 1 |
| [NC-05] | Consider Adding a Block/Deny-List | 3 |
| [NC-06] | Use the Modern Upgradeable Contract Paradigm | 12 |
| [NC-07] | Control Structures Not Complying with Best Practices | 40 |
| [NC-08] | Use Unchecked for Divisions on Constant or Immutable Values | 1 |
| [NC-09] | Duplicated require()/revert() Checks | 4 |
| [NC-10] | Consider Adding Emergency-Stop Functionality | 3 |
| [NC-11] | Ensure Non-Empty Check for Bytes in Function Parameters | 3 |
| [NC-12] | Consider Enabling `--via-ir` for Enhanced Code Transparency and Auditability | 6 |
| [NC-13] | Events in public function missing sender information | 10 |
| [NC-14] | Ensure Events Emission Prior to External Calls to Prevent Out-of-Order Issues | 2 |
| [NC-15] | Use `delete` Instead of Assigning Values to `false` | 1 |
| [NC-16] | `Solidity Style Guide`: Lines are too long | 15 |
| [NC-17] | Floating Pragmas in Contract | 1 |
| [NC-18] | `Solidity Style Guide`: Function order not compliant | 9 |
| [NC-19] | Function/Constructor Argument Names Not in mixedCase | 10 |
| [NC-20] | Avoid Hard-Coded Addresses | 1 |
| [NC-21] | High Cyclomatic Complexity in Functions | 1 |
| [NC-22] | Non-uppercase/Constant-case Naming for `immutable` Variables | 2 |
| [NC-23] | Non-Standard Annotations Detected Use `@inheritdoc` instead | 3 |
| [NC-24] | Unnecessary Initialization of `int/uint` with `zero` value | 6 |
| [NC-25] | Invalid NatSpec Comment Style | 1 |
| [NC-26] | Replace `constant` with `immutable` for calculated values | 13 |
| [NC-27] | Leverage Recent Solidity Features with `0.8.21` | 6 |
| [NC-28] | Upgrade `openzeppelin` to the Latest Version - 5.0.0 | 16 |
| [NC-29] | Using Low-Level Call for Transfers | 2 |
| [NC-30] | Consider Avoid Loops in Public Functions | 1 |
| [NC-31] | Constants Should Be Defined Rather Than Using Magic Numbers | 4 |
| [NC-32] | Lack of Parameter Validation in Constructor/Initializer | 5 |
| [NC-33] | Missing NatSpec Descriptions for Modifier Declarations | 2 |
| [NC-34] | Refactor `msg.sender` Checks into a Modifier | 3 |
| [NC-35] | Large multiples of ten should use scientific notation | 2 |
| [NC-36] | Refactor Multiple Mappings into a Struct for Improved Code Readability | 4 |
| [NC-37] | Consider Using Named Mappings | 7 |
| [NC-38] | NatSpec: Contract declarations should have `@author` tag | 5 |
| [NC-39] | NatSpec: Contract declarations should have `@dev` tag | 3 |
| [NC-40] | NatSpec: Function `@return` tag is missing | 16 |
| [NC-41] | NatSpec: Function declarations should have descriptions | 13 |
| [NC-42] | NatSpec: Function declarations should have `@notice` tag | 16 |
| [NC-43] | NatSpec: Function/Constructor `@param` tag is missing | 33 |
| [NC-44] | Internal/Private State variable should have descriptions | 4 |
| [NC-45] | Modifiers Missing NatSpec `@param` Tag | 3 |
| [NC-46] | NatSpec: Public State variable declarations should have descriptions | 5 |
| [NC-47] | Non-constant/non-immutable variables using all capital letters | 1 |
| [NC-48] | Non-specific Imports | 27 |
| [NC-49] | Explicit Visibility Recommended in Variable/Function Definitions | 2 |
| [NC-50] | Outdated Solidity Version | 1 |
| [NC-51] | Layout Order Does Not Comply with `Solidity Style Guide` | 1 |
| [NC-52] | Unnecessary Use of `override` Keyword | 19 |
| [NC-53] | Named Imports of Parent Contracts Are Missing | 15 |
| [NC-54] | `public` functions not called by the contract should be declared `external` instead | 5 |
| [NC-55] | Lack of Reentrancy Guards in Functions With Transfer Hooks | 2 |
| [NC-56] | Inclusive Language: Replace Sensitive Terms | 16 |
| [NC-57] | Implement Value Comparison Checks in Setter Functions to Prevent Redundant State Updates | 8 |
| [NC-58] | Prefer Casting to `bytes` or `bytes32` Over `abi.encodePacked()` for Single Arguments | 1 |
| [NC-59] | Use Structs for Returning Multiple Variables | 1 |
| [NC-60] | Use a single file for all system-wide constants | 15 |
| [NC-61] | Missing event or timelock for critical parameter change | 5 |
| [NC-62] | Consider Limit Input Array Length | 2 |
| [NC-63] | Presence of Unutilized Imports in the Contract | 2 |
| [NC-64] | Eliminate Unused Internal Functions for Code Clarity | 1 |
| [NC-65] | Add Inline Comments for Unnamed Function Parameters | 2 |
| [NC-66] | Consider using `constant` instead of passing zero as a function argument | 2 |
| [NC-67] | `Solidity Style Guide`: Non-public Variable Names Without Leading Underscores | 18 |
| [NC-68] | Contracts should have full test coverage | 1 |
| [NC-69] | Insufficient Invariant Tests for Contracts | 1 |
| [NC-70] | Implement Formal Verification Proofs to Improve Security | 1 |

Total: 469 instances of 72 issues

## Gas Findings

|    | Issue | Instances | Total Gas Saved |
|----|-------|:---------:|:---------:|
| [G-01] | Optimize `<array>.length` Look-up in For-Loops | 4 | 12 |
| [G-02] | Optimize Zero Checks Using Assembly | 20 | 1160 |
| [G-03] | Consider using `assembly` to write address storage values if the address variable is mutable | 3 | - |
| [G-04] | Unnecessary Stack Variable Cache for State Variables | 3 | 9 |
| [G-05] | Consider Caching Multiple Accesses to Mappings/Arrays | 6 | 600 |
| [G-06] | Use `unchecked {}` for division of `uint`s to save gas | 2 | 40 |
| [G-07] | Optimize Gas by Using Do-While Loops | 4 | 1020 |
| [G-08] | Use Assembly for Efficient Event Emission | 19 | 34200 |
| [G-09] | Enable `--via-ir` for Potential Gas Savings Through Cross-Function Optimizations | 6 | 1500 |
| [G-10] | Optimize External Calls with Assembly for Memory Efficiency | 7 | 1540 |
| [G-11] | Consider Using `>=`/`<=` Instead of `>`/`<` | 12 | 36 |
| [G-12] | Use Assembly for Hash Calculations | 3 | 3015 |
| [G-13] | Inline `internal` Functions That Called Once | 4 | 80 |
| [G-14] | Optimize Gas Spend Using `0.8.20` and Optimizer Features | 6 | - |
| [G-15] | Consider Using Solady's Gas Optimized Lib for Math | 4 | - |
| [G-16] | Trade-offs Between Modifiers and Internal Functions | 23 | 241500 |
| [G-17] | Avoid Using `_msgSender()` if not Supporting EIP-2771 | 2 | 32 |
| [G-18] | Optimize Gas Usage by Combining Mappings into a Struct | 4 | 168 |
| [G-19] | Using nested `if` save gas | 3 | 18 |
| [G-20] | Avoid Zero to Non-Zero Storage Writes Where Possible | 5 | 110500 |
| [G-21] | Optimize Deployment Size by Fine-tuning IPFS Hash | 6 | 63600 |
| [G-22] | Optimize Function Names for Gas Savings | 6 | 120 |
| [G-23] | Using bools for storage incurs overhead | 1 | 100 |
| [G-24] | Optimize Boolean States with `uint256(1/2)` | 1 | 17000 |
| [G-25] | Consider Packing Small `uint` When it's Possible | 2 | 41600 |
| [G-26] | Consider Marking Constructors As `payable` | 5 | 120 |
| [G-27] | Mark Functions That Revert For Normal Users As `payable` | 24 | 504 |
| [G-28] | Use Pre-Increment/Decrement (++i/--i) to Save Gas | 2 | 10 |
| [G-29] | Avoid Unnecessary Public Variables | 13 | 286000 |
| [G-30] | Optimize by Using Assembly for Low-Level Calls' Return Data | 2 | 318 |
| [G-31] | Consider Using selfbalance() Over address(this).balance | 1 | - |
| [G-32] | Missing Initial Value Check in Set Functions | 12 | 9600 |
| [G-33] | State Variables Should Be `immutable` Since They Are Only Set in the Constructor | 2 | 4200 |
| [G-34] | Avoid Using Small Size Integers | 8 | 48 |
| [G-35] | Optimize Gas by Splitting `if() revert` Statements | 8 | - |
| [G-36] | State variables should be cached (stack/memory/storage pointer) rather than re-reading them from storage | 12 | 1164 |
| [G-37] | Optimize Storage with Byte Truncation for Time Related State Variables | 4 | 8000 |
| [G-38] | Avoid Zero Transfers to Save Gas | 3 | 300 |
| [G-39] | Optimize Unsigned Integer Comparison With Zero | 3 | 12 |
| [G-40] | Optimize Increment and Decrement in loops with `unchecked` keyword | 4 | 240 |
| [G-41] | Use `unchecked` for Math Operations if they already checked | 1 | 85 |
| [G-42] | Delete Unused Internal Functions to save gas on deployment | 1 | - |
| [G-43] | Delete Unused State Variables | 1 | 20000 |
| [G-44] | Optimize Gas by Using Only Named Returns | 18 | 792 |

Total: 281 instances of 45 issues with 849343 gas saved

## Disputed Findings

|    | Issue | Instances |
|----|-------|:---------:|
| [D-01] | Casting `block.timestamp` to Smaller Integer Types Limit Contract Lifespan | 2 |
| [D-02] | Explicit Visibility Recommended in Variable/Function Definitions | 2 |
| [D-03] | Centralized Control Risk in Privileged Functions | 3 |
| [D-04] | Unchecked Return Values of `transfer()/transferFrom()` | 1 |
| [D-05] | Unsafe use of `transfer()/transferFrom()` with IERC20 | 1 |
| [D-06] | Mint to zero address | 2 |
| [D-07] | Owner can renounce Ownership | 1 |





Total: 4 instances of 2 issues

## Medium Findings Details

### [M-01] Low Level Calls to Custom Addresses

Contracts should avoid making low-level calls to custom addresses, especially if these calls are based on address parameters in the function. 
Such behavior can lead to unexpected execution of untrusted code. Instead, consider using Solidity's high-level function calls or contract interactions.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

404: (bool success,) = (beneficiary).call{value: amount}("");
```

| [Line #404](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L404) | </details>


### [M-02] Possible Vulnerability to Fee-On-Transfer Accounting Issues

Contracts transfer funds using the `transferFrom()` function but do not verify that the actual number of tokens received matches the input amount to the transfer.
This could lead to accounting issues if the token involves a fee on transfer.
An attacker might exploit latent funds to get a free credit.
To prevent this, consider checking the balance before and after the transfer and use the difference as the actual amount received.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

253: IERC20(asset).safeTransfer(wallet, amount);
```

| [Line #253](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L253) | </details>


### [M-03] Potential Gas Griefing Due to Non-Handling of Return Data in External Calls

Due to the EVM architecture, return data (bool success,) has to be stored.
However, when 'out' and 'outsize' values are given (0,0), this storage disappears.
This can lead to potential gas griefing/theft issues, especially when dealing with external contracts.
```solidity
assembly {
    success: = call(gas(), dest, amount, 0, 0)
}
require(success, "transfer failed");

```
Consider using a safe call pattern above to avoid these issues.
The following instances show the unsafe external call patterns found in the code.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

404: (bool success,) = (beneficiary).call{value: amount}("");
```

| [Line #404](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L404) | </details>

## Low Findings Details

### [L-01] State Address Changes Should Be a Two-Step Procedure

Direct state address changes in a function can be risky, as they don't allow for a verification step before the change is made.
It's safer to implement a two-step process where the new address is first proposed, then later confirmed, allowing for more control and the chance to catch errors or malicious activity.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/USDe.sol

/// @audit `minter` is changed
25: minter = newMinter;
```

| [Line #25](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L25) |  </details>


### [L-02] Consider to Use `SafeCast` for Casting

Casting from larger types  to smaller ones can potentially lead to overflows and thus unexpected behavior.
For instance, when a `uint256` value gets cast to `uint8`, it could end up as an entirely different, much smaller number due to the reduction in bits. 

OpenZeppelin's SafeCast library provides functions for safe type conversions, throwing an error whenever an overflow would occur.
It is generally recommended to use SafeCast or similar protective measures when performing type conversions to ensure the accuracy of your computations and the security of your contracts.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit cast from `uint256 nonce` to `uint64`
379: uint256 invalidatorSlot = uint64(nonce) >> 8;
/// @audit cast from `uint256 nonce` to `uint8`
380: uint256 invalidatorBit = 1 << uint8(nonce);
```

| [Line #379](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L379) | [Line #380](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L380) | </details>


### [L-03] Missing Contract-Existence Checks Before Low-Level Calls

When making low-level calls, it's crucial to ensure the existence of the contract at the specified address. 
If the contract doesn't exist at the given address, low-level calls will still return success, potentially causing errors in the code execution.
Therefore, alongside zero-address checks, adding an additional check to verify that <address>.code.length > 0 before making low-level calls would be recommended.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

404: (bool success,) = (beneficiary).call{value: amount}("");
```

| [Line #404](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L404) | </details>


### [L-04] Using Draft Contract Imports

Draft contracts, like those from OpenZeppelin, although audited and safe to use, are based on non-finalized EIPs and may be subject to breaking changes in even minor releases.
If a bug is found in the version of OpenZeppelin you're using, and the bug-fix release contains breaking changes, this could lead to unnecessary delays in porting and testing replacement contracts.

It's recommended to have extensive test coverage to detect differences automatically and a plan for testing new versions of these contracts if they change unexpectedly.
Consider creating a forked version of the file rather than importing it from the package, and manually patching your fork as changes are made, to maintain better control over your dependencies and to mitigate this risk.

<details>
<summary><i>2 issue instances in 2 files:</i></summary>

```solidity
File: contracts/USDe.sol

6: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
```

| [Line #6](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L6) | 
```solidity
File: contracts/StakedUSDe.sol

11: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
```

| [Line #11](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L11) | </details>


### [L-05] Risk of Revert from External Calls in Unbounded For-loops

Executing external calls within unbounded for-loops poses a significant risk of transaction revert.
A failure in one of the iterations can lead to the entire transaction being reverted.
Furthermore, excessive iterations may consume an exorbitant amount of gas, potentially reaching the block gas limit, causing the transaction to fail.
This can result in unintended outcomes, especially if a majority of the iterations would have otherwise succeeded without the problematic call.
To enhance contract reliability and manage gas consumption efficiently, consider limiting the number of iterations in such loops, and implement robust error-handling mechanisms for potential failures in the looped external calls.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit 1 external calls in unbounded for-loop -> 424: for (uint256 i = 0; i < addresses.length; ++i) {
426: token.safeTransferFrom(benefactor, addresses[i], amountToTransfer);
```

| [Line #426](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L426) | </details>


### [L-06] Potential loss of precision in division operations

Division by large numbers may result in the result being zero, due to Solidity not supporting fractions. Consider requiring a minimum amount for the numerator to ensure that it is always larger than the denominator.

<details>
<summary><i>2 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

425: uint256 amountToTransfer = (amount * ratios[i]) / 10_000;
```

| [Line #425](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L425) | 
```solidity
File: contracts/StakedUSDe.sol

180: return ((VESTING_PERIOD - timeSinceLastDistribution) * vestingAmount) / VESTING_PERIOD;
```

| [Line #180](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L180) | </details>


### [L-07] Missing `address(0)` Check in Constructor/Initializer

The constructor/initializer does not include a check for `address(0)` when initializing state variables that hold addresses.
Initializing a state variable with `address(0)` can lead to unintended behavior and vulnerabilities in the contract, 
such as sending funds to an inaccessible address. 
It is recommended to include a validation step to ensure that address parameters are not set to `address(0)`.

<details>
<summary><i>10 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit `_custodians` has lack of `address(0)` check before use
/// @audit `_custodians` has lack of `address(0)` check before use
111: constructor(
    IUSDe _usde,
    address[] memory _assets,
    address[] memory _custodians,
    address _admin,
    uint256 _maxMintPerBlock,
    uint256 _maxRedeemPerBlock
  ) {
```

| [Line #111](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L111) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit `_asset` has lack of `address(0)` check before use
/// @audit `initialRewarder` passed to inherited constructor is not checked for `address(0)`
/// @audit `owner` passed to inherited constructor is not checked for `address(0)`
42: constructor(IERC20 _asset, address initialRewarder, address owner) StakedUSDe(_asset, initialRewarder, owner) {
```

| [Line #42](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L42) | 
```solidity
File: contracts/USDeSilo.sol

/// @audit `stakingVault` has lack of `address(0)` check before use
/// @audit `usde` has lack of `address(0)` check before use
18: constructor(address stakingVault, address usde) {
```

| [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L18) | </details>


### [L-08] Function Parameters in Public Accessible Functions Need `address(0)` Check

Parameters of type `address` in your functions should be checked to ensure that they are not assigned the null address (`address(0x0)`). 
Failure to validate these parameters can lead to transaction reverts, wasted gas, the need for transaction resubmission, and may even require redeployment of contracts within the protocol in certain situations.
Implement checks for `address(0x0)` to avoid these potential issues.

<details>
<summary><i>55 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

/// @audit `newMinter` parameter without address(0) check
23: function setMinter(address newMinter) external onlyOwner {
/// @audit `to` parameter without address(0) check
28: function mint(address to, uint256 amount) external {
```

| [Line #23](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L23) | [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L28) | 
```solidity
File: contracts/EthenaMinting.sol

/// @audit `_delegateTo` parameter without address(0) check
235: function setDelegatedSigner(address _delegateTo) external {
/// @audit `_removedSigner` parameter without address(0) check
241: function removeDelegatedSigner(address _removedSigner) external {
/// @audit `asset` parameter without address(0) check
247: function transferToCustody(address wallet, address asset, uint256 amount) external nonReentrant onlyRole(MINTER_ROLE) {
/// @audit `asset` parameter without address(0) check
259: function removeSupportedAsset(address asset) external onlyRole(DEFAULT_ADMIN_ROLE) {
/// @audit `asset` parameter without address(0) check
265: function isSupportedAsset(address asset) external view returns (bool) {
/// @audit `custodian` parameter without address(0) check
270: function removeCustodianAddress(address custodian) external onlyRole(DEFAULT_ADMIN_ROLE) {
/// @audit `minter` parameter without address(0) check
277: function removeMinterRole(address minter) external onlyRole(GATEKEEPER_ROLE) {
/// @audit `redeemer` parameter without address(0) check
283: function removeRedeemerRole(address redeemer) external onlyRole(GATEKEEPER_ROLE) {
/// @audit `sender` parameter without address(0) check
377: function verifyNonce(address sender, uint256 nonce) public view override returns (bool, uint256, uint256, uint256) {
```

| [Line #235](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L235) | [Line #241](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L241) | [Line #247](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L247) | [Line #259](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L259) | [Line #265](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L265) | [Line #270](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L270) | [Line #277](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L277) | [Line #283](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L283) | [Line #377](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L377) | 
```solidity
File: contracts/StakedUSDe.sol

/// @audit `target` parameter without address(0) check
106: function addToBlacklist(address target, bool isFullBlacklisting)
    external
    onlyRole(BLACKLIST_MANAGER_ROLE)
    notOwner(target)
  {
/// @audit `target` parameter without address(0) check
120: function removeFromBlacklist(address target, bool isFullBlacklisting)
    external
    onlyRole(BLACKLIST_MANAGER_ROLE)
    notOwner(target)
  {
/// @audit `token` parameter without address(0) check
/// @audit `to` parameter without address(0) check
138: function rescueTokens(address token, uint256 amount, address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
/// @audit `from` parameter without address(0) check
148: function redistributeLockedAmount(address from, address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
/// @audit `address` parameter without address(0) check
257: function renounceRole(bytes32, address) public virtual override {
```

| [Line #106](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L106) | [Line #120](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L120) | [Line #138](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L138) | [Line #148](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L148) | [Line #257](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L257) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit `receiver` parameter without address(0) check
/// @audit `owner` parameter without address(0) check
52: function withdraw(uint256 assets, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
/// @audit `receiver` parameter without address(0) check
/// @audit `owner` parameter without address(0) check
65: function redeem(uint256 shares, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
/// @audit `receiver` parameter without address(0) check
78: function unstake(address receiver) external {
/// @audit `owner` parameter without address(0) check
95: function cooldownAssets(uint256 assets, address owner) external ensureCooldownOn returns (uint256) {
/// @audit `owner` parameter without address(0) check
111: function cooldownShares(uint256 shares, address owner) external ensureCooldownOn returns (uint256) {
```

| [Line #52](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L52) | [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L65) | [Line #78](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L78) | [Line #95](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L95) | [Line #111](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L111) | 
```solidity
File: contracts/USDeSilo.sol

/// @audit `to` parameter without address(0) check
28: function withdraw(address to, uint256 amount) external onlyStakingVault {
```

| [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L28) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

/// @audit `newAdmin` parameter without address(0) check
25: function transferAdmin(address newAdmin) external onlyRole(DEFAULT_ADMIN_ROLE) {
/// @audit `account` parameter without address(0) check
41: function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
/// @audit `account` parameter without address(0) check
50: function revokeRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
/// @audit `account` parameter without address(0) check
58: function renounceRole(bytes32 role, address account) public virtual override notAdmin(role) {
```

| [Line #25](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L25) | [Line #41](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L41) | [Line #50](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L50) | [Line #58](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L58) | </details>


### [L-09] Potential Re-org Attack Vector

The contract appears to deploy new contracts using the `new` keyword.
In a re-org attack scenario, such deployments can be exploited by a malicious actor who might rewrite the blockchain's history and deploy the contract at an expected address. 

Consider deploying the contract via `CREATE2` opcode with a specific salt that includes `msg.sender` and the existing contract address.
This will ensure a predictable contract address, reducing the chances of such an attack.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDeV2.sol

43: silo = new USDeSilo(address(this), address(_asset));
```

| [Line #43](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L43) | </details>


### [L-10] Possible Revert ERC20 Transfers with Zero Value

Some ERC20 tokens (for example, LEND) revert on attempts to transfer a zero value.
This can become a problem in any contract that doesn't handle these cases correctly.

If a token transfer fails, any additional logic in a function might also be affected or even fail entirely.
Therefore, contracts interacting with ERC20 tokens should account for the possibility that a zero-value transfer might revert.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit `amountToTransfer` has not been checked for zero value before transfer
426: token.safeTransferFrom(benefactor, addresses[i], amountToTransfer);
```

| [Line #426](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L426) | </details>


### [L-11] Large Token Transfers Could Revert For Certain Tokens

Tokens like:

- [COMP (Compound Protocol)](https://github.com/compound-finance/compound-protocol/blob/a3214f67b73310d547e00fc578e8355911c9d376/contracts/Governance/Comp.sol#L115-L142)
- [UNI (Uniswap)](https://github.com/Uniswap/governance/blob/eabd8c71ad01f61fb54ed6945162021ee419998e/contracts/Uni.sol#L209-L236)

have limit set by `uint96`.

Transfers that approach or exceed this limit will revert.
Be cautious of such transfers, especially if batching is not implemented to handle these scenarios.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

253: IERC20(asset).safeTransfer(wallet, amount);
```

| [Line #253](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L253) |  </details>


### [L-12] Potential Unbounded Gas Consumption on External Calls

External calls in your code don't specify a gas limit, which can lead to scenarios where the recipient consumes all transaction's gas causing it to revert. 
Consider using `addr.call{gas: <amount>}("")` to set a gas limit and prevent potential reversion due to gas consumption.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

404: (bool success,) = (beneficiary).call{value: amount}("");
```

| [Line #404](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L404) | </details>


### [L-13] State variables are not limited to a reasonable range

It's advisable to introduce minimum and maximum value constraints for state variables.
By not setting bounds, there's a potential for users to face adverse effects, including potential griefing attacks.
Ensuring that state variables operate within a known range can enhance safety and predictability.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

438: maxMintPerBlock = _maxMintPerBlock;
445: maxRedeemPerBlock = _maxRedeemPerBlock;
```

| [Line #438](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L438) | [Line #445](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L445) | </details>


### [L-14] Use two-step ownership transfers is import `Ownable2Step`

Single-step ownership transfers can be risky due to the potential for errors or wrong address inputs.
In worst-case scenarios, your contract could become `ownerless`.
To mitigate these risks, consider using a two-step ownership transfers.
In this process, a new potential owner is first designated, and then they must accept the ownership to complete the transfer.
This two-step procedure ensures a more secure and reliable transfer of contract ownership.

Used single step ownership transfer in constructor.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/USDe.sol

20: _transferOwnership(admin);
```

| [Line #20](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L20) | </details>


## Non-critical Findings Details

### [NC-01] Use `delete` to clear variables instead of zero assignment

Rather than merely setting a variable to zero, you can use the `delete` keyword to reset it to its default value.
This action is especially relevant for complex data types like arrays or mappings where the default is not necessarily zero.
Using `delete` not only provides explicit clarity that you intend to reset a variable, but it can also result in more concise and intuitive code.

Moreover, in certain contexts, delete might help save gas if optimizer off.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDeV2.sol

83: userCooldown.cooldownEnd = 0;
84: userCooldown.underlyingAmount = 0;
```

| [Line #83](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L83) | [Line #84](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L84) | </details>


### [NC-02] Use `bytes.concat()` instead of `abi.encodePacked()`

Solidity version 0.8.4 introduces `bytes.concat()` for concatenating byte arrays, which is more efficient than using `abi.encodePacked()`.
It is recommended to use `bytes.concat()` instead of `abi.encodePacked()` and upgrade to at least Solidity version 0.8.4 if required.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

49: bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(abi.encodePacked(EIP712_DOMAIN));
```

| [Line #49](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L49) | </details>


### [NC-03] Constants on the right side of comparison statements

Placing constants on the left side of comparison statements can help prevent accidental assignments and improve code readability.
In languages like C, placing constants on the left can protect against unintended assignments that would be treated as true conditions, leading to bugs.
Although Solidity does not have this specific issue, using the same practice can still be beneficial for code readability and consistency.

Consider placing constants on the left side of comparison operators like `==`, `!=`, `<`, `>`, `<=`, and `>=`."

<details>
<summary><i>12 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

120: if (_assets.length == 0) revert NoAssetsProvided();
344: if (order.collateral_amount == 0) revert InvalidAmount();
345: if (order.usde_amount == 0) revert InvalidAmount();
360: if (route.addresses.length == 0) {
370: if (totalRatio != 10_000) {
378: if (nonce == 0) revert InvalidNonce();
383: if (invalidator & invalidatorBit != 0) revert InvalidNonce();
430: if (remainingBalance > 0) {
```

| [Line #120](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L120) | [Line #344](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L344) | [Line #345](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L345) | [Line #360](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L360) | [Line #370](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L370) | [Line #378](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L378) | [Line #383](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L383) | [Line #430](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L430) | 
```solidity
File: contracts/StakedUSDe.sol

51: if (amount == 0) revert InvalidAmount();
193: if (_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();
```

| [Line #51](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L51) | [Line #193](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L193) | 
```solidity
File: contracts/StakedUSDeV2.sol

28: if (cooldownDuration != 0) revert OperationNotAllowed();
34: if (cooldownDuration == 0) revert OperationNotAllowed();
```

| [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L28) | [Line #34](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L34) | </details>


### [NC-04] Variable Names Not in mixedCase

State or Local Variable names in your contract don't align with the Solidity naming convention.
For clarity and code consistency, it's recommended to use mixedCase for local and state variables that are not constants, and add a trailing underscore for internal variables.
Adhering to this convention helps in improving code readability and maintenance.
[More information in Documentation](https://docs.soliditylang.org/en/v0.8.20/style-guide.html#function-names)

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit - Variable name `taker_order_hash` should be in mixedCase
340: bytes32 taker_order_hash = hashOrder(order);
```

| [Line #340](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L340) | </details>


### [NC-05] Consider Adding a Block/Deny-List

While adding a block or deny-list may increase the level of centralization in the contract, it provides an additional layer of security by preventing hackers from using stolen tokens or carrying out other malicious activities.

Although it's a trade-off, a block or deny-list can help improve the overall security posture of the contract.

<details>
<summary><i>3 issue instances in 3 files:</i></summary>

```solidity
File: contracts/USDe.sol

15: contract USDe is Ownable2Step, ERC20Burnable, ERC20Permit, IUSDeDefinitions {
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L15) | 
```solidity
File: contracts/EthenaMinting.sol

21: contract EthenaMinting is IEthenaMinting, SingleAdminAccessControl, ReentrancyGuard {
```

| [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L21) | 
```solidity
File: contracts/USDeSilo.sol

12: contract USDeSilo is IUSDeSiloDefinitions {
```

| [Line #12](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L12) | </details>


### [NC-06] Use the Modern Upgradeable Contract Paradigm

Contract uses a non-upgradeable design.
Transitioning to an upgradeable contract structure is more aligned with contemporary smart contract practices.
This approach not only enhances flexibility but also allows for continuous improvement and adaptation, ensuring the contract stays relevant and robust in an ever-evolving ecosystem.

<details>
<summary><i>12 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

/// @audit - Contract `USDe` is not upgradeable
15: contract USDe is Ownable2Step, ERC20Burnable, ERC20Permit, IUSDeDefinitions {
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L15) | 
```solidity
File: contracts/EthenaMinting.sol

/// @audit - Contract `EthenaMinting` is not upgradeable
21: contract EthenaMinting is IEthenaMinting, SingleAdminAccessControl, ReentrancyGuard {
```

| [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L21) | 
```solidity
File: contracts/StakedUSDe.sol

/// @audit - Contract `StakedUSDe` is not upgradeable
21: contract StakedUSDe is SingleAdminAccessControl, ReentrancyGuard, ERC20Permit, ERC4626, IStakedUSDe {
```

| [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L21) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit - Contract `StakedUSDeV2` is not upgradeable
15: contract StakedUSDeV2 is IStakedUSDeCooldown, StakedUSDe {
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L15) | 
```solidity
File: contracts/USDeSilo.sol

/// @audit - Contract `USDeSilo` is not upgradeable
12: contract USDeSilo is IUSDeSiloDefinitions {
```

| [Line #12](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L12) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

/// @audit - Contract `SingleAdminAccessControl` is not upgradeable
13: abstract contract SingleAdminAccessControl is IERC5313, ISingleAdminAccessControl, AccessControl {
```

| [Line #13](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L13) | </details>


### [NC-07] Control Structures Not Complying with Best Practices

Following best practices for control structures in solidity code is vital for readability and maintainability. The control structures in contracts, libraries, functions, and structs should adhere to the following standards:

- Braces denoting the body should open on the same line as the declaration and close on their own line at the same indentation level as the beginning of the declaration. 
- A single space should precede the opening brace. 
- Control structures such as 'if', 'else', 'while', and 'for' should also follow these spacing and brace placement recommendations.

It is advised to revisit the [control structures](https://docs.soliditylang.org/en/latest/style-guide.html#control-structures) sections in documentation to ensure conformity with these best practices, fostering cleaner and more maintainable code.

<details>
<summary><i>40 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

/// @audit `Return or revert statement should be on new line.`
19: if (admin == address(0)) revert ZeroAddressException();
/// @audit `Return or revert statement should be on new line.`
29: if (msg.sender != minter) revert OnlyMinter();
```

| [Line #19](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L19) | [Line #29](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L29) | 
```solidity
File: contracts/EthenaMinting.sol

/// @audit `Return or revert statement should be on new line.`
98: if (mintedPerBlock[block.number] + mintAmount > maxMintPerBlock) revert MaxMintPerBlockExceeded();
/// @audit `Return or revert statement should be on new line.`
105: if (redeemedPerBlock[block.number] + redeemAmount > maxRedeemPerBlock) revert MaxRedeemPerBlockExceeded();
/// @audit `Return or revert statement should be on new line.`
119: if (address(_usde) == address(0)) revert InvalidUSDeAddress();
/// @audit `Return or revert statement should be on new line.`
120: if (_assets.length == 0) revert NoAssetsProvided();
/// @audit `Return or revert statement should be on new line.`
121: if (_admin == address(0)) revert InvalidZeroAddress();
/// @audit `Return or revert statement should be on new line.`
169: if (order.order_type != OrderType.MINT) revert InvalidOrder();
/// @audit `Return or revert statement should be on new line.`
171: if (!verifyRoute(route, order.order_type)) revert InvalidRoute();
/// @audit `Return or revert statement should be on new line.`
172: if (!_deduplicateOrder(order.benefactor, order.nonce)) revert Duplicate();
/// @audit `Return or revert statement should be on new line.`
201: if (order.order_type != OrderType.REDEEM) revert InvalidOrder();
/// @audit `Return or revert statement should be on new line.`
203: if (!_deduplicateOrder(order.benefactor, order.nonce)) revert Duplicate();
/// @audit `Return or revert statement should be on new line.`
248: if (wallet == address(0) || !_custodianAddresses.contains(wallet)) revert InvalidAddress();
/// @audit `Return or revert statement should be on new line.`
251: if (!success) revert TransferFailed();
/// @audit `Return or revert statement should be on new line.`
260: if (!_supportedAssets.remove(asset)) revert InvalidAssetAddress();
/// @audit `Return or revert statement should be on new line.`
271: if (!_custodianAddresses.remove(custodian)) revert InvalidCustodianAddress();
/// @audit `Return or revert statement should be on new line.`
342: if (!(signer == order.benefactor || delegatedSigner[signer][order.benefactor])) revert InvalidSignature();
/// @audit `Return or revert statement should be on new line.`
343: if (order.beneficiary == address(0)) revert InvalidAmount();
/// @audit `Return or revert statement should be on new line.`
344: if (order.collateral_amount == 0) revert InvalidAmount();
/// @audit `Return or revert statement should be on new line.`
345: if (order.usde_amount == 0) revert InvalidAmount();
/// @audit `Return or revert statement should be on new line.`
346: if (block.timestamp > order.expiry) revert SignatureExpired();
/// @audit `Return or revert statement should be on new line.`
378: if (nonce == 0) revert InvalidNonce();
/// @audit `Return or revert statement should be on new line.`
383: if (invalidator & invalidatorBit != 0) revert InvalidNonce();
/// @audit `Return or revert statement should be on new line.`
402: if (asset == NATIVE_TOKEN) {
      if (address(this).balance < amount) revert InvalidAmount();
/// @audit `Return or revert statement should be on new line.`
405: if (!success) revert TransferFailed();
/// @audit `Return or revert statement should be on new line.`
407: if (!_supportedAssets.contains(asset)) revert UnsupportedAsset();
/// @audit `Return or revert statement should be on new line.`
421: if (!_supportedAssets.contains(asset) || asset == NATIVE_TOKEN) revert UnsupportedAsset();
```

| [Line #98](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L98) | [Line #105](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L105) | [Line #119](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L119) | [Line #120](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L120) | [Line #121](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L121) | [Line #169](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L169) | [Line #171](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L171) | [Line #172](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L172) | [Line #201](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L201) | [Line #203](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L203) | [Line #248](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L248) | [Line #251](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L251) | [Line #260](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L260) | [Line #271](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L271) | [Line #342](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L342) | [Line #343](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L343) | [Line #344](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L344) | [Line #345](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L345) | [Line #346](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L346) | [Line #378](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L378) | [Line #383](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L383) | [Line #402](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L402) | [Line #405](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L405) | [Line #407](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L407) | [Line #421](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L421) | 
```solidity
File: contracts/StakedUSDe.sol

/// @audit `Return or revert statement should be on new line.`
51: if (amount == 0) revert InvalidAmount();
/// @audit `Return or revert statement should be on new line.`
57: if (target == owner()) revert CantBlacklistOwner();
/// @audit `Return or revert statement should be on new line.`
90: if (getUnvestedAmount() > 0) revert StillVesting();
/// @audit `Return or revert statement should be on new line.`
139: if (address(token) == asset()) revert InvalidToken();
/// @audit `Return or revert statement should be on new line.`
193: if (_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();
```

| [Line #51](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L51) | [Line #57](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L57) | [Line #90](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L90) | [Line #139](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L139) | [Line #193](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L193) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit `Return or revert statement should be on new line.`
28: if (cooldownDuration != 0) revert OperationNotAllowed();
/// @audit `Return or revert statement should be on new line.`
34: if (cooldownDuration == 0) revert OperationNotAllowed();
/// @audit `Return or revert statement should be on new line.`
96: if (assets > maxWithdraw(owner)) revert ExcessiveWithdrawAmount();
/// @audit `Return or revert statement should be on new line.`
112: if (shares > maxRedeem(owner)) revert ExcessiveRedeemAmount();
```

| [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L28) | [Line #34](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L34) | [Line #96](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L96) | [Line #112](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L112) | 
```solidity
File: contracts/USDeSilo.sol

/// @audit `Return or revert statement should be on new line.`
24: if (msg.sender != STAKING_VAULT) revert OnlyStakingVault();
```

| [Line #24](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L24) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

/// @audit `Return or revert statement should be on new line.`
18: if (role == DEFAULT_ADMIN_ROLE) revert InvalidAdminChange();
/// @audit `Return or revert statement should be on new line.`
26: if (newAdmin == msg.sender) revert InvalidAdminChange();
/// @audit `Return or revert statement should be on new line.`
32: if (msg.sender != _pendingDefaultAdmin) revert NotPendingAdmin();
```

| [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L18) | [Line #26](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L26) | [Line #32](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L32) | </details>


### [NC-08] Use Unchecked for Divisions on Constant or Immutable Values

Unsigned divisions on constant or immutable values do not result in overflow.
Therefore, these operations can be marked as unchecked, optimizing gas usage without compromising safety.

For instance, if `a` is an unsigned integer and `b` is a constant or immutable, a / b can be safely rewritten as: unchecked { a / b }

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDe.sol

180: return ((VESTING_PERIOD - timeSinceLastDistribution) * vestingAmount) / VESTING_PERIOD;
```

| [Line #180](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L180) | </details>


### [NC-09] Duplicated require()/revert() Checks

Duplicated require() or revert() checks should be refactored to a modifier or function.
This helps in maintaining a clean and organized codebase and saves deployment costs.

<details>
<summary><i>4 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

172: if (!_deduplicateOrder(order.benefactor, order.nonce)) revert Duplicate();
203: if (!_deduplicateOrder(order.benefactor, order.nonce)) revert Duplicate();
251: if (!success) revert TransferFailed();
405: if (!success) revert TransferFailed();
```

| [Line #172](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L172) | [Line #203](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L203) | [Line #251](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L251) | [Line #405](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L405) | </details>


### [NC-10] Consider Adding Emergency-Stop Functionality

Smart contracts that hold significant value, interact with external contracts, or have complex logic should include an emergency-stop mechanism for added security. This allows pausing certain contract functionalities in case of emergencies, mitigating potential damages.

This contract seems to lack such a mechanism. Implementing an emergency stop can enhance contract security and reliability.

<details>
<summary><i>3 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

1: No emergency stop pattern found
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L1) | 
```solidity
File: contracts/StakedUSDe.sol

1: No emergency stop pattern found
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L1) | 
```solidity
File: contracts/StakedUSDeV2.sol

1: No emergency stop pattern found
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L1) | </details>


### [NC-11] Ensure Non-Empty Check for Bytes in Function Parameters

To avoid mistakenly accepting empty bytes as valid parameters, it is advisable to implement checks for non-empty bytes within functions.
This ensures that empty bytes are not treated as valid inputs, preventing potential issues.

<details>
<summary><i>3 issue instances in 1 files:</i></summary>

```solidity
File: contracts/SingleAdminAccessControl.sol

41: function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
50: function revokeRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
58: function renounceRole(bytes32 role, address account) public virtual override notAdmin(role) {
```

| [Line #41](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L41) | [Line #50](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L50) | [Line #58](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L58) | </details>


### [NC-12] Consider Enabling `--via-ir` for Enhanced Code Transparency and Auditability

The `--via-ir` command line option enables Solidity's IR-based code generator, offering a level of transparency and auditability superior to the traditional, direct-to-EVM method.
The Intermediate Representation (IR) in Yul serves as an intermediary, offering a more transparent view of how the Solidity code is transformed into EVM bytecode.

While it does introduce slight semantic variations, these are mostly in areas unlikely to impact the typical contract's behavior.
It is encouraged to test this feature to gain its benefits, which include making the code generation process more transparent and auditable.

[Solidity Documentation](https://docs.soliditylang.org/en/v0.8.20/ir-breaking-changes.html#solidity-ir-based-codegen-changes).

<details>
<summary><i>1 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

```
</details>


### [NC-13] Events in public function missing sender information

Events should include the sender information when emitted in `public` or `external` functions for better traceability.

<details>
<summary><i>10 issue instances in 5 files:</i></summary>

```solidity
File: contracts/USDe.sol

/// @audit external function `setMinter()` emits an event without sender information
24: emit MinterUpdated(newMinter, minter);
```

| [Line #24](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L24) | 
```solidity
File: contracts/EthenaMinting.sol

/// @audit external function `transferToCustody()` emits an event without sender information
255: emit CustodyTransfer(wallet, asset, amount);
/// @audit external function `removeSupportedAsset()` emits an event without sender information
261: emit AssetRemoved(asset);
/// @audit external function `removeCustodianAddress()` emits an event without sender information
272: emit CustodianAddressRemoved(custodian);
/// @audit public function `addSupportedAsset()` emits an event without sender information
294: emit AssetAdded(asset);
/// @audit public function `addCustodianAddress()` emits an event without sender information
302: emit CustodianAddressAdded(custodian);
```

| [Line #255](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L255) | [Line #261](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L261) | [Line #272](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L272) | [Line #294](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L294) | [Line #302](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L302) | 
```solidity
File: contracts/StakedUSDe.sol

/// @audit external function `transferInRewards()` emits an event without sender information
97: emit RewardsReceived(amount, newVestingAmount);
/// @audit external function `redistributeLockedAmount()` emits an event without sender information
154: emit LockedAmountRedistributed(from, to, amountToDistribute);
```

| [Line #97](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L97) | [Line #154](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L154) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit external function `setCooldownDuration()` emits an event without sender information
133: emit CooldownDurationUpdated(previousDuration, cooldownDuration);
```

| [Line #133](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L133) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

/// @audit external function `transferAdmin()` emits an event without sender information
28: emit AdminTransferRequested(_currentDefaultAdmin, newAdmin);
```

| [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L28) | </details>


### [NC-14] Ensure Events Emission Prior to External Calls to Prevent Out-of-Order Issues

It's essential to ensure that events follow the best practice of check-effects-interaction and are emitted before any external calls to prevent out-of-order events due to reentrancy.
Emitting events post external interactions may cause them to be out of order due to reentrancy, which can be misleading or erroneous for event listeners.
[Refer to the Solidity Documentation for best practices.](https://solidity.readthedocs.io/en/latest/security-considerations.html#reentrancy)

<details>
<summary><i>2 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit `call()` before `CustodyTransfer` event emit
255: emit CustodyTransfer(wallet, asset, amount);
```

| [Line #255](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L255) | 
```solidity
File: contracts/StakedUSDe.sol

/// @audit `safeTransferFrom()` before `RewardsReceived` event emit
97: emit RewardsReceived(amount, newVestingAmount);
```

| [Line #97](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L97) | </details>


### [NC-15] Use `delete` Instead of Assigning Values to `false`

The use of the delete keyword is recommended over simply assigning values to false when you intend to reset the state of a variable.
The delete keyword more closely aligns with the semantic intent of clearing or resetting a variable.
This practice also makes the code more readable and highlights the change in state, which may encourage a more thorough audit of the surrounding logic.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

242: delegatedSigner[_removedSigner][msg.sender] = false;
```

| [Line #242](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L242) | </details>


### [NC-16] `Solidity Style Guide`: Lines are too long

It is generally recommended that lines in the source code should not exceed 80-120 characters.
Multiline output parameters and return statements should follow the same style recommended for wrapping long lines found in the Maximum Line Length section.

<details>
<summary><i>15 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

36: "Order(uint8 order_type,uint256 expiry,uint256 nonce,address benefactor,address beneficiary,address collateral_asset,uint256 collateral_amount,uint256 usde_amount)"
95: /// @notice ensure that the already minted USDe in the actual block plus the amount to be minted is below the maxMintPerBlock var
102: /// @notice ensure that the already redeemed USDe in the actual block plus the amount to be redeemed is below the maxRedeemPerBlock var
247: function transferToCustody(address wallet, address asset, uint256 amount) external nonReentrant onlyRole(MINTER_ROLE) {
306: /// @dev Return cached value if chainId matches cache, otherwise recomputes separator, to prevent replay attack across forks
339: function verifyOrder(Order calldata order, Signature calldata signature) public view override returns (bool, bytes32) {
```

| [Line #36](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L36) | [Line #95](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L95) | [Line #102](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L102) | [Line #247](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L247) | [Line #306](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L306) | [Line #339](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L339) | 
```solidity
File: contracts/StakedUSDe.sol

17: * @notice The StakedUSDe contract allows users to stake USDe tokens and earn a portion of protocol LST and perpetual yield that is allocated
18: * to stakers by the Ethena DAO governance voted yield distribution algorithm.  The algorithm seeks to balance the stability of the protocol by funding
31: /// @notice The role which prevents an address to transfer, stake, or unstake. The owner of the contract can redirect address staking balance if an address is in full restricting mode.
```

| [Line #17](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L17) | [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L18) | [Line #31](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L31) | 
```solidity
File: contracts/StakedUSDeV2.sol

10: * @notice The StakedUSDeV2 contract allows users to stake USDe tokens and earn a portion of protocol LST and perpetual yield that is allocated
11: * to stakers by the Ethena DAO governance voted yield distribution algorithm.  The algorithm seeks to balance the stability of the protocol by funding
13: * @dev If cooldown duration is set to zero, the StakedUSDeV2 behavior changes to follow ERC4626 standard and disables cooldownShares and cooldownAssets methods. If cooldown duration is greater than zero, the ERC4626 withdrawal and redeem functions are disabled, breaking the ERC4626 standard, and enabling the cooldownShares and the cooldownAssets functions.
75: /// @notice Claim the staking amount after the cooldown has finished. The address can only retire the full amount of assets.
76: /// @dev unstake can be called after cooldown have been set to 0, to let accounts to be able to claim remaining assets locked at Silo
124: /// @notice Set cooldown duration. If cooldown duration is set to zero, the StakedUSDeV2 behavior changes to follow ERC4626 standard and disables cooldownShares and cooldownAssets methods. If cooldown duration is greater than zero, the ERC4626 withdrawal and redeem functions are disabled, breaking the ERC4626 standard, and enabling the cooldownShares and the cooldownAssets functions.
```

| [Line #10](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L10) | [Line #11](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L11) | [Line #13](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L13) | [Line #75](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L75) | [Line #76](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L76) | [Line #124](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L124) | </details>


### [NC-17] Floating Pragmas in Contract

Floating pragmas may lead to unintended vulnerabilities due to different compiler versions.
It is recommended to lock the Solidity version in pragma statements.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/USDeSilo.sol

2: pragma solidity ^0.8.0;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L2) | </details>


### [NC-18] `Solidity Style Guide`: Function order not compliant

Ordering helps readers identify which functions they can call and to find the constructor and fallback definitions easier.
But there are contracts in the project that do not comply with this.
Functions should be grouped according to their visibility and ordered:
- constructor 
- receive function (if exists)
- fallback function (if exists)
- external
- public
- internal
- private.

<details>
<summary><i>9 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit `private` function `_deduplicateOrder()` declared before `internal` function `_transferToBeneficiary()`
391: function _deduplicateOrder(address sender, uint256 nonce) private returns (bool) {
401: function _transferToBeneficiary(address beneficiary, address asset, uint256 amount) internal {
```

| [Line #391](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L391) | [Line #401](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L401) | 
```solidity
File: contracts/StakedUSDe.sol

/// @audit `internal` function `_beforeTokenTransfer()` declared before `public` function `renounceRole()`
244: function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
257: function renounceRole(bytes32, address) public virtual override {
```

| [Line #244](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L244) | [Line #257](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L257) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit `public` function `redeem()` declared before `external` function `unstake()`
65: function redeem(uint256 shares, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
78: function unstake(address receiver) external {
```

| [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L65) | [Line #78](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L78) | </details>


### [NC-19] Function/Constructor Argument Names Not in mixedCase

Underscore before of after function argument names is a common convention in Solidity NOT a documentation requirement.

Function arguments should use mixedCase for better readability and consistency with Solidity style guidelines. 
Examples of good practice include: initialSupply, account, recipientAddress, senderAddress, newOwner. 
[More information in Documentation](https://docs.soliditylang.org/en/v0.8.20/style-guide.html#function-argument-names)

Rule exceptions
- Allow constant variable name/symbol/decimals to be lowercase (ERC20).
- Allow `_` at the beginning of the mixedCase match for `private variables` and `unused parameters`.

<details>
<summary><i>10 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

219: function setMaxMintPerBlock(uint256 _maxMintPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {
224: function setMaxRedeemPerBlock(uint256 _maxRedeemPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {
235: function setDelegatedSigner(address _delegateTo) external {
241: function removeDelegatedSigner(address _removedSigner) external {
436: function _setMaxMintPerBlock(uint256 _maxMintPerBlock) internal {
443: function _setMaxRedeemPerBlock(uint256 _maxRedeemPerBlock) internal {
110: constructor(
    IUSDe _usde,
    address[] memory _assets,
    address[] memory _custodians,
    address _admin,
    uint256 _maxMintPerBlock,
    uint256 _maxRedeemPerBlock
  ) {
```

| [Line #219](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L219) | [Line #224](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L224) | [Line #235](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L235) | [Line #241](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L241) | [Line #436](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L436) | [Line #443](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L443) | [Line #110](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L110) | 
```solidity
File: contracts/StakedUSDe.sol

225: function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
  {
70: constructor(IERC20 _asset, address _initialRewarder, address _owner)
    ERC20("Staked USDe", "stUSDe")
    ERC4626(_asset)
    ERC20Permit("stUSDe")
  {
```

| [Line #225](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L225) | [Line #70](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L70) | 
```solidity
File: contracts/StakedUSDeV2.sol

42: constructor(IERC20 _asset, address initialRewarder, address owner) StakedUSDe(_asset, initialRewarder, owner) {
```

| [Line #42](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L42) | </details>


### [NC-20] Avoid Hard-Coded Addresses

It's often better to declare these addresses as immutable and assign them via constructor arguments.
This approach allows the code to remain consistent across deployments on different networks and avoids recompilation when addresses change.

Refactoring your code in this manner can improve its maintainability and flexibility.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

52: address private constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
```

| [Line #52](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L52) | </details>


### [NC-21] High Cyclomatic Complexity in Functions

Functions with high cyclomatic complexity are harder to understand, test, and maintain.
Consider breaking down these blocks into more manageable units, by splitting things into utility functions,
by reducing nesting, and by using early returns.

[Learn More About Cyclomatic Complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity)

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit function `verifyRoute` has a cyclomatic complexity of 6
351: function verifyRoute(Route calldata route, OrderType orderType) public view override returns (bool) {
```

| [Line #351](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L351) | </details>


### [NC-22] Non-uppercase/Constant-case Naming for `immutable` Variables
For better readability and adherence to common naming conventions, variable names declared as immutable should be written in all uppercase letters.
<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

72: uint256 private immutable _chainId;
75: bytes32 private immutable _domainSeparator;
```

| [Line #72](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L72) | [Line #75](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L75) | </details>


### [NC-23] Non-Standard Annotations Detected Use `@inheritdoc` instead

Using non-standard annotations like `@dev see Ellipsis` can lead to inconsistencies and lack of clarity in your smart contract documentation.
It's recommended to use the `@inheritdoc` annotation for enhanced clarity and uniformity in smart contract development.

`@inheritdoc` copies all state variables, internal and public function comments from the base contract to avoid repetition.

<details>
<summary><i>3 issue instances in 2 files:</i></summary>

```solidity
File: contracts/StakedUSDeV2.sol

50: * @dev See {IERC4626-withdraw}.
63: * @dev See {IERC4626-redeem}.
```

| [Line #50](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L50) | [Line #63](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L63) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

63: * @dev See {IERC5313-owner}.
```

| [Line #63](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L63) | </details>


### [NC-24] Unnecessary Initialization of `int/uint` with `zero` value

By default, `int/uint` variables in Solidity are initialized to `zero`.
Explicitly setting variables to zero during their declaration is redundant and might cause confusion.
Removing the explicit zero initialization can improve code readability and understanding.

<details>
<summary><i>6 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

126: for (uint256 i = 0; i < _assets.length; i++) {
130: for (uint256 j = 0; j < _custodians.length; j++) {
356: uint256 totalRatio = 0;
363: for (uint256 i = 0; i < route.addresses.length; ++i) {
423: uint256 totalTransferred = 0;
424: for (uint256 i = 0; i < addresses.length; ++i) {
```

| [Line #126](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L126) | [Line #130](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L130) | [Line #356](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L356) | [Line #363](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L363) | [Line #423](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L423) | [Line #424](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L424) | </details>


### [NC-25] Invalid NatSpec Comment Style

NatSpec comments in Solidity are meant to be recognized by tools for a variety of purposes such as documentation generation.
The correct style is to use `///` for single-line comments and `/* ... */` for multi-line comments.
Incorrect styles can cause tools to not recognize the comments as intended.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

68: // @notice custodian addresses
```

| [Line #68](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L68) | </details>


### [NC-26] Replace `constant` with `immutable` for calculated values

Using `constant` with expressions like `keccak256()` or any calculations can be misleading. 

In Solidity, the `constant` modifier should be reserved for values that are truly constant and hardcoded into the contract. For values that are calculated or derived during the contract's creation, consider using the `immutable` modifier instead.

Shifting to `immutable` in such instances provides better clarity about the nature of the value, indicating that it's set once during contract initialization and remains unchanged afterward.

<details>
<summary><i>13 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

28: bytes32 private constant EIP712_DOMAIN =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
32: bytes32 private constant ROUTE_TYPE = keccak256("Route(address[] addresses,uint256[] ratios)");
35: bytes32 private constant ORDER_TYPE = keccak256(
    "Order(uint8 order_type,uint256 expiry,uint256 nonce,address benefactor,address beneficiary,address collateral_asset,uint256 collateral_amount,uint256 usde_amount)"
  );
40: bytes32 private constant MINTER_ROLE = keccak256("MINTER_ROLE");
43: bytes32 private constant REDEEMER_ROLE = keccak256("REDEEMER_ROLE");
46: bytes32 private constant GATEKEEPER_ROLE = keccak256("GATEKEEPER_ROLE");
49: bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(abi.encodePacked(EIP712_DOMAIN));
55: bytes32 private constant EIP_712_NAME = keccak256("EthenaMinting");
58: bytes32 private constant EIP712_REVISION = keccak256("1");
```

| [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L28) | [Line #32](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L32) | [Line #35](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L35) | [Line #40](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L40) | [Line #43](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L43) | [Line #46](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L46) | [Line #49](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L49) | [Line #55](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L55) | [Line #58](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L58) | 
```solidity
File: contracts/StakedUSDe.sol

26: bytes32 private constant REWARDER_ROLE = keccak256("REWARDER_ROLE");
28: bytes32 private constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
30: bytes32 private constant SOFT_RESTRICTED_STAKER_ROLE = keccak256("SOFT_RESTRICTED_STAKER_ROLE");
32: bytes32 private constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
```

| [Line #26](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L26) | [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L28) | [Line #30](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L30) | [Line #32](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L32) | </details>


### [NC-27] Leverage Recent Solidity Features with `0.8.21`

The recent updates in Solidity provide several features and optimizations that, when leveraged appropriately, can significantly improve your contract's code clarity and maintainability.
Key enhancements include the use of push0 for placing 0 on the stack for EVM versions starting from "Shanghai", making your code simpler and more straightforward.
Moreover, Solidity has extended NatSpec documentation support to enum and struct definitions, facilitating more comprehensive and insightful code documentation.

Additionally, the re-implementation of the UnusedAssignEliminator and UnusedStoreEliminator in the Solidity optimizer provides the ability to remove unused assignments in deeply nested loops.
This results in a cleaner, more efficient contract code, reducing clutter and potential points of confusion during code review or debugging.
It's recommended to make full use of these features and optimizations to enhance the robustness and readability of your smart contracts.

<details>
<summary><i>6 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

2: pragma solidity 0.8.19;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L2) | 
```solidity
File: contracts/EthenaMinting.sol

2: pragma solidity 0.8.19;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L2) | 
```solidity
File: contracts/StakedUSDe.sol

2: pragma solidity 0.8.19;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L2) | 
```solidity
File: contracts/StakedUSDeV2.sol

2: pragma solidity 0.8.19;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L2) | 
```solidity
File: contracts/USDeSilo.sol

2: pragma solidity ^0.8.0;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L2) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

2: pragma solidity 0.8.19;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L2) | </details>


### [NC-28] Upgrade `openzeppelin` to the Latest Version - 5.0.0

These contracts import contracts from @openzeppelin/contracts but they are not using the latest version.
For more information, please visit: [OpenZeppelin GitHub Releases](https://github.com/OpenZeppelin/openzeppelin-contracts/releases)
It is recommended to always use the latest version to take advantage of updates and security fixes.

<details>
<summary><i>16 issue instances in 5 files:</i></summary>

```solidity
File: contracts/USDe.sol

4: import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
5: import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
6: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
7: import "@openzeppelin/contracts/access/Ownable2Step.sol";
```

| [Line #4](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L4) | [Line #5](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L5) | [Line #6](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L6) | [Line #7](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L7) | 
```solidity
File: contracts/EthenaMinting.sol

9: import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
10: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
11: import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
12: import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
```

| [Line #9](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L9) | [Line #10](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L10) | [Line #11](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L11) | [Line #12](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L12) | 
```solidity
File: contracts/StakedUSDe.sol

8: import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
9: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
10: import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
11: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
```

| [Line #8](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L8) | [Line #9](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L9) | [Line #10](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L10) | [Line #11](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L11) | 
```solidity
File: contracts/USDeSilo.sol

4: import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
5: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
```

| [Line #4](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L4) | [Line #5](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L5) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

4: import "@openzeppelin/contracts/access/AccessControl.sol";
5: import "@openzeppelin/contracts/interfaces/IERC5313.sol";
```

| [Line #4](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L4) | [Line #5](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L5) | </details>


### [NC-29] Using Low-Level Call for Transfers

Directly using low-level calls for Ether transfers can introduce vulnerabilities and obscure the intent of your transfers.
Adopt modern Solidity best practices by switching to recognized libraries like `SafeTransferLib.safeTransferETH` or `Address.sendValue`.
This ensures safer transactions, enhances code clarity, and aligns with the standards of the Solidity community.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

250: (bool success,) = wallet.call{value: amount}("");
404: (bool success,) = (beneficiary).call{value: amount}("");
```

| [Line #250](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L250) | [Line #404](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L404) | </details>


### [NC-30] Consider Avoid Loops in Public Functions

Using loops within `public` or `external` functions can pose risks and inefficiencies.
Unpredictable gas consumption due to loop iterations can hinder a function's usability and cost-effectiveness. 
Furthermore, if the loop's logic can be externally influenced or altered, it might be exploited to intentionally drain gas, making the function impractical or uneconomical to call.
To ensure consistent performance and avoid potential vulnerabilities, it's advisable to avoid or limit loops in public functions, especially if their logic can change.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

363: for (uint256 i = 0; i < route.addresses.length; ++i) {
```

| [Line #363](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L363) | </details>


### [NC-31] Constants Should Be Defined Rather Than Using Magic Numbers

Magic numbers are hardcoded numerical values used directly in the code, making it harder to read and maintain.
Consider using constants instead of magic numbers.

<details>
<summary><i>4 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit 10_000
370: if (totalRatio != 10_000) {
/// @audit 10_000
425: uint256 amountToTransfer = (amount * ratios[i]) / 10_000;
```

| [Line #370](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L370) | [Line #425](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L425) | 
```solidity
File: contracts/StakedUSDe.sol

/// @audit 18
185: return 18;
```

| [Line #185](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L185) |  </details>


### [NC-32] Lack of Parameter Validation in Constructor/Initializer

The constructor/initializer doesn't validate input parameters before assigning them to state variables.
It is crucial to ensure that input parameters meet certain conditions to avoid unexpected states or behaviors in the contract.
Consider adding appropriate checks or constraints.

<details>
<summary><i>5 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit `_maxMintPerBlock` is not validated before use
/// @audit `_maxRedeemPerBlock` is not validated before use
111: constructor(
    IUSDe _usde,
    address[] memory _assets,
    address[] memory _custodians,
    address _admin,
    uint256 _maxMintPerBlock,
    uint256 _maxRedeemPerBlock
  ) {
```

| [Line #111](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L111) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit `_asset` is not validated before use
42: constructor(IERC20 _asset, address initialRewarder, address owner) StakedUSDe(_asset, initialRewarder, owner) {
```

| [Line #42](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L42) | </details>


### [NC-33] Missing NatSpec Descriptions for Modifier Declarations

Modifiers in the contract should include NatSpec comments, specifically with the `@dev` or `@notice` tags to elucidate their role and input parameters.
These annotations assist in offering a clearer insight into the contract's operation for developers, auditors, and end-users.
[Additional Details in Solidity Documentation](https://docs.soliditylang.org/en/latest/natspec-format.html)

<details>
<summary><i>2 issue instances in 2 files:</i></summary>

```solidity
File: contracts/USDeSilo.sol

23: modifier onlyStakingVault() {
```

| [Line #23](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L23) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

17: modifier notAdmin(bytes32 role) {
```

| [Line #17](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L17) | </details>


### [NC-34] Refactor `msg.sender` Checks into a Modifier

Functions that are only allowed to be called by a specific actor should use a modifier to check if the caller is the specified actor (e.g., owner, specific role, etc.).
Using `require` to check `msg.sender` in the function body is less efficient and less clear.

Consider refactoring these `require` statements into a modifier for better readability, organization, and gas efficiency.

<details>
<summary><i>3 issue instances in 2 files:</i></summary>

```solidity
File: contracts/USDe.sol

29: if (msg.sender != minter) revert OnlyMinter();
```

| [Line #29](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L29) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

26: if (newAdmin == msg.sender) revert InvalidAdminChange();
32: if (msg.sender != _pendingDefaultAdmin) revert NotPendingAdmin();
```

| [Line #26](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L26) | [Line #32](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L32) | </details>


### [NC-35] Large multiples of ten should use scientific notation

Large multiples of ten should use scientific notation (e.g., 1e4) instead of decimal literals (e.g., 10000)
for better code readability.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit `10_000` should be written as `1e4`
370: if (totalRatio != 10_000) {
/// @audit `10_000` should be written as `1e4`
425: uint256 amountToTransfer = (amount * ratios[i]) / 10_000;
```

| [Line #370](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L370) | [Line #425](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L425) | </details>


### [NC-36] Refactor Multiple Mappings into a Struct for Improved Code Readability

Combining multiple address/ID mappings into a single mapping to a struct can enhance code clarity and maintainability. 
Consider refactoring multiple mappings into a single mapping with a struct for cleaner code structure.
This arrangement also promotes a more organized contract structure, making it easier for developers to navigate and understand.

<details>
<summary><i>4 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

78: mapping(address => mapping(uint256 => uint256)) private _orderBitmaps;
86: mapping(address => mapping(address => bool)) public delegatedSigner;
81: mapping(uint256 => uint256) public mintedPerBlock;
83: mapping(uint256 => uint256) public redeemedPerBlock;
```

| [Line #78](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L78) | [Line #86](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L86) | [Line #81](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L81) | [Line #83](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L83) | </details>


### [NC-37] Consider Using Named Mappings

As of Solidity version 0.8.18, it is possible to use named mappings to clarify the purpose of each mapping in the code. 
It is recommended to use this feature for better code readability and maintainability.

More information: [Solidity 0.8.18 Release Announcement](https://blog.soliditylang.org/2023/02/01/solidity-0.8.18-release-announcement/)

<details>
<summary><i>7 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

78: mapping(address => mapping(uint256 => uint256)) private _orderBitmaps;
81: mapping(uint256 => uint256) public mintedPerBlock;
83: mapping(uint256 => uint256) public redeemedPerBlock;
86: mapping(address => mapping(address => bool)) public delegatedSigner;
381: mapping(uint256 => uint256) storage invalidatorStorage = _orderBitmaps[sender];
393: mapping(uint256 => uint256) storage invalidatorStorage = _orderBitmaps[sender];
```

| [Line #78](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L78) | [Line #81](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L81) | [Line #83](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L83) | [Line #86](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L86) | [Line #381](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L381) | [Line #393](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L393) | 
```solidity
File: contracts/StakedUSDeV2.sol

18: mapping(address => UserCooldown) public cooldowns;
```

| [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L18) | </details>


### [NC-38] NatSpec: Contract declarations should have `@author` tag

In the world of decentralized code, giving credit is key. NatSpec's `@author` tag acknowledges the minds behind the code.
It appears this Solidity contract omits the `@author` directive in its NatSpec annotations.
Properly attributing code to its contributors not only recognizes effort but also aids in establishing trust and credibility.
[Dive Deeper into NatSpec Guidelines](https://docs.soliditylang.org/en/develop/natspec-format.html)

<details>
<summary><i>5 issue instances in 5 files:</i></summary>

```solidity
File: contracts/USDe.sol

15: contract USDe is Ownable2Step, ERC20Burnable, ERC20Permit, IUSDeDefinitions {
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L15) | 
```solidity
File: contracts/EthenaMinting.sol

21: contract EthenaMinting is IEthenaMinting, SingleAdminAccessControl, ReentrancyGuard {
```

| [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L21) | 
```solidity
File: contracts/StakedUSDe.sol

21: contract StakedUSDe is SingleAdminAccessControl, ReentrancyGuard, ERC20Permit, ERC4626, IStakedUSDe {
```

| [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L21) | 
```solidity
File: contracts/StakedUSDeV2.sol

15: contract StakedUSDeV2 is IStakedUSDeCooldown, StakedUSDe {
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L15) | 
```solidity
File: contracts/USDeSilo.sol

12: contract USDeSilo is IUSDeSiloDefinitions {
```

| [Line #12](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L12) | </details>


### [NC-39] NatSpec: Contract declarations should have `@dev` tag

NatSpec comments are a critical part of Solidity's documentation system, designed to help developers and others understand the behavior and purpose of a contract.
The `@dev` tag, in particular, provides context and insight into the contract's development considerations.
A missing `@dev` comment can lead to misunderstandings about the contract, making it harder for others to contribute to or use the contract effectively.
Therefore, it's highly recommended to include `@dev` comments in the documentation to enhance code readability and maintainability.
[Refer to NatSpec Documentation](https://docs.soliditylang.org/en/develop/natspec-format.html)

<details>
<summary><i>3 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

21: contract EthenaMinting is IEthenaMinting, SingleAdminAccessControl, ReentrancyGuard {
```

| [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L21) | 
```solidity
File: contracts/StakedUSDe.sol

21: contract StakedUSDe is SingleAdminAccessControl, ReentrancyGuard, ERC20Permit, ERC4626, IStakedUSDe {
```

| [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L21) | 
```solidity
File: contracts/USDeSilo.sol

12: contract USDeSilo is IUSDeSiloDefinitions {
```

| [Line #12](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L12) | </details>


### [NC-40] NatSpec: Function `@return` tag is missing

Natural Specification (NatSpec) comments are crucial for understanding the role of function arguments in your Solidity code.
Including `@return` tag will not only improve your code's readability but also its maintainability by clearly defining each argument's purpose.

[More information in Documentation](https://docs.soliditylang.org/en/develop/natspec-format.html)

<details>
<summary><i>16 issue instances in 4 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit Missed @return ``
265: function isSupportedAsset(address asset) external view returns (bool) {
/// @audit Missed @return ``
316: function hashOrder(Order calldata order) public view override returns (bytes32) {
/// @audit Missed @return ``
320: function encodeOrder(Order calldata order) public pure returns (bytes memory) {
/// @audit Missed @return ``
334: function encodeRoute(Route calldata route) public pure returns (bytes memory) {
/// @audit Missed @return `, `
339: function verifyOrder(Order calldata order, Signature calldata signature) public view override returns (bool, bytes32) {
/// @audit Missed @return ``
351: function verifyRoute(Route calldata route, OrderType orderType) public view override returns (bool) {
/// @audit Missed @return `, , , `
377: function verifyNonce(address sender, uint256 nonce) public view override returns (bool, uint256, uint256, uint256) {
/// @audit Missed @return ``
391: function _deduplicateOrder(address sender, uint256 nonce) private returns (bool) {
```

| [Line #265](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L265) | [Line #316](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L316) | [Line #320](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L320) | [Line #334](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L334) | [Line #339](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L339) | [Line #351](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L351) | [Line #377](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L377) | [Line #391](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L391) | 
```solidity
File: contracts/StakedUSDe.sol

/// @audit Missed @return ``
166: function totalAssets() public view override returns (uint256) {
/// @audit Missed @return ``
173: function getUnvestedAmount() public view returns (uint256) {
/// @audit Missed @return ``
184: function decimals() public pure override(ERC4626, ERC20) returns (uint8) {
```

| [Line #166](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L166) | [Line #173](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L173) | [Line #184](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L184) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit Missed @return ``
52: function withdraw(uint256 assets, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
/// @audit Missed @return ``
65: function redeem(uint256 shares, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
/// @audit Missed @return ``
95: function cooldownAssets(uint256 assets, address owner) external ensureCooldownOn returns (uint256) {
/// @audit Missed @return ``
111: function cooldownShares(uint256 shares, address owner) external ensureCooldownOn returns (uint256) {
```

| [Line #52](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L52) | [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L65) | [Line #95](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L95) | [Line #111](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L111) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

/// @audit Missed @return ``
65: function owner() public view virtual returns (address) {
```

| [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L65) | </details>


### [NC-41] NatSpec: Function declarations should have descriptions

The Ethereum Natural Specification Format (NatSpec) is an integral part of the Solidity language, serving as a rich, machine-readable, language-agnostic metadata tool.

Documenting all functions, irrespective of their visibility, significantly enhances code readability and auditability.
This is especially vital in complex projects, where clear comprehension of functions, their arguments, and returns is paramount.

Specifically, the `@notice` tag should be used for explanations that anyone should understand, making it a key element in providing a clear understanding of a function's intention.
[More information in Documentation](https://docs.soliditylang.org/en/develop/natspec-format.html)

<details>
<summary><i>13 issue instances in 5 files:</i></summary>

```solidity
File: contracts/USDe.sol

18: constructor(address admin) ERC20("USDe", "USDe") ERC20Permit("USDe") {
23: function setMinter(address newMinter) external onlyOwner {
28: function mint(address to, uint256 amount) external {
33: function renounceOwnership() public view override onlyOwner {
```

| [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L18) | [Line #23](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L23) | [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L28) | [Line #33](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L33) | 
```solidity
File: contracts/EthenaMinting.sol

111: constructor(
    IUSDe _usde,
    address[] memory _assets,
    address[] memory _custodians,
    address _admin,
    uint256 _maxMintPerBlock,
    uint256 _maxRedeemPerBlock
  ) {
320: function encodeOrder(Order calldata order) public pure returns (bytes memory) {
334: function encodeRoute(Route calldata route) public pure returns (bytes memory) {
```

| [Line #111](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L111) | [Line #320](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L320) | [Line #334](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L334) | 
```solidity
File: contracts/StakedUSDeV2.sol

52: function withdraw(uint256 assets, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
65: function redeem(uint256 shares, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
```

| [Line #52](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L52) | [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L65) | 
```solidity
File: contracts/USDeSilo.sol

18: constructor(address stakingVault, address usde) {
28: function withdraw(address to, uint256 amount) external onlyStakingVault {
```

| [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L18) | [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L28) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

31: function acceptAdmin() external {
65: function owner() public view virtual returns (address) {
```

| [Line #31](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L31) | [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L65) | </details>


### [NC-42] NatSpec: Function declarations should have `@notice` tag

In Solidity, the `@notice` tag in NatSpec comments is used to provide important explanations to end users about what a function does. 
It appears that this contract's function declarations are missing `@notice` tags in their NatSpec annotations.

The absence of `@notice` tags reduces the contract's transparency and could lead to misunderstandings about a function's purpose and behavior.
Note that the Solidity compiler treats comments beginning with `///` or `/**` as `@notice` tags if one wasn't explicitly provided.
[Learn More About NatSpec Guidelines](https://docs.soliditylang.org/en/develop/natspec-format.html)

<details>
<summary><i>16 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

18: constructor(address admin) ERC20("USDe", "USDe") ERC20Permit("USDe") {
23: function setMinter(address newMinter) external onlyOwner {
28: function mint(address to, uint256 amount) external {
33: function renounceOwnership() public view override onlyOwner {
```

| [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L18) | [Line #23](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L23) | [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L28) | [Line #33](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L33) | 
```solidity
File: contracts/EthenaMinting.sol

111: constructor(
    IUSDe _usde,
    address[] memory _assets,
    address[] memory _custodians,
    address _admin,
    uint256 _maxMintPerBlock,
    uint256 _maxRedeemPerBlock
  ) {
320: function encodeOrder(Order calldata order) public pure returns (bytes memory) {
334: function encodeRoute(Route calldata route) public pure returns (bytes memory) {
```

| [Line #111](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L111) | [Line #320](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L320) | [Line #334](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L334) | 
```solidity
File: contracts/StakedUSDe.sol

148: function redistributeLockedAmount(address from, address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
184: function decimals() public pure override(ERC4626, ERC20) returns (uint8) {
257: function renounceRole(bytes32, address) public virtual override {
```

| [Line #148](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L148) | [Line #184](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L184) | [Line #257](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L257) | 
```solidity
File: contracts/StakedUSDeV2.sol

52: function withdraw(uint256 assets, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
65: function redeem(uint256 shares, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
```

| [Line #52](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L52) | [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L65) | 
```solidity
File: contracts/USDeSilo.sol

18: constructor(address stakingVault, address usde) {
28: function withdraw(address to, uint256 amount) external onlyStakingVault {
```

| [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L18) | [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L28) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

31: function acceptAdmin() external {
65: function owner() public view virtual returns (address) {
```

| [Line #31](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L31) | [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L65) | </details>


### [NC-43] NatSpec: Function/Constructor `@param` tag is missing

Natural Specification (NatSpec) comments are crucial for understanding the role of function arguments in your Solidity code.
Including `@param` tags will not only improve your code's readability but also its maintainability by clearly defining each argument's purpose.

[More information in Documentation](https://docs.soliditylang.org/en/develop/natspec-format.html)

<details>
<summary><i>33 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

/// @audit Missed @param `admin`
18: constructor(address admin) ERC20("USDe", "USDe") ERC20Permit("USDe") {
/// @audit Missed @param `newMinter`
23: function setMinter(address newMinter) external onlyOwner {
/// @audit Missed @param `to, amount`
28: function mint(address to, uint256 amount) external {
```

| [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L18) | [Line #23](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L23) | [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L28) | 
```solidity
File: contracts/EthenaMinting.sol

/// @audit Missed @param `_usde, _assets, _custodians, _admin, _maxMintPerBlock, _maxRedeemPerBlock`
111: constructor(
    IUSDe _usde,
    address[] memory _assets,
    address[] memory _custodians,
    address _admin,
    uint256 _maxMintPerBlock,
    uint256 _maxRedeemPerBlock
  ) {
/// @audit Missed @param `route`
162: function mint(Order calldata order, Route calldata route, Signature calldata signature)
    external
    override
    nonReentrant
    onlyRole(MINTER_ROLE)
    belowMaxMintPerBlock(order.usde_amount)
  {
/// @audit Missed @param `_maxMintPerBlock`
219: function setMaxMintPerBlock(uint256 _maxMintPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {
/// @audit Missed @param `_maxRedeemPerBlock`
224: function setMaxRedeemPerBlock(uint256 _maxRedeemPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {
/// @audit Missed @param `_delegateTo`
235: function setDelegatedSigner(address _delegateTo) external {
/// @audit Missed @param `_removedSigner`
241: function removeDelegatedSigner(address _removedSigner) external {
/// @audit Missed @param `wallet, asset, amount`
247: function transferToCustody(address wallet, address asset, uint256 amount) external nonReentrant onlyRole(MINTER_ROLE) {
/// @audit Missed @param `asset`
259: function removeSupportedAsset(address asset) external onlyRole(DEFAULT_ADMIN_ROLE) {
/// @audit Missed @param `asset`
265: function isSupportedAsset(address asset) external view returns (bool) {
/// @audit Missed @param `custodian`
270: function removeCustodianAddress(address custodian) external onlyRole(DEFAULT_ADMIN_ROLE) {
/// @audit Missed @param `asset`
290: function addSupportedAsset(address asset) public onlyRole(DEFAULT_ADMIN_ROLE) {
/// @audit Missed @param `custodian`
298: function addCustodianAddress(address custodian) public onlyRole(DEFAULT_ADMIN_ROLE) {
/// @audit Missed @param `order`
316: function hashOrder(Order calldata order) public view override returns (bytes32) {
/// @audit Missed @param `order`
320: function encodeOrder(Order calldata order) public pure returns (bytes memory) {
/// @audit Missed @param `route`
334: function encodeRoute(Route calldata route) public pure returns (bytes memory) {
/// @audit Missed @param `order, signature`
339: function verifyOrder(Order calldata order, Signature calldata signature) public view override returns (bool, bytes32) {
/// @audit Missed @param `route, orderType`
351: function verifyRoute(Route calldata route, OrderType orderType) public view override returns (bool) {
/// @audit Missed @param `sender, nonce`
377: function verifyNonce(address sender, uint256 nonce) public view override returns (bool, uint256, uint256, uint256) {
/// @audit Missed @param `sender, nonce`
391: function _deduplicateOrder(address sender, uint256 nonce) private returns (bool) {
/// @audit Missed @param `beneficiary, asset, amount`
401: function _transferToBeneficiary(address beneficiary, address asset, uint256 amount) internal {
/// @audit Missed @param `amount, asset, benefactor, addresses, ratios`
413: function _transferCollateral(
    uint256 amount,
    address asset,
    address benefactor,
    address[] calldata addresses,
    uint256[] calldata ratios
  ) internal {
/// @audit Missed @param `_maxMintPerBlock`
436: function _setMaxMintPerBlock(uint256 _maxMintPerBlock) internal {
/// @audit Missed @param `_maxRedeemPerBlock`
443: function _setMaxRedeemPerBlock(uint256 _maxRedeemPerBlock) internal {
```

| [Line #111](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L111) | [Line #162](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L162) | [Line #219](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L219) | [Line #224](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L224) | [Line #235](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L235) | [Line #241](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L241) | [Line #247](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L247) | [Line #259](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L259) | [Line #265](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L265) | [Line #270](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L270) | [Line #290](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L290) | [Line #298](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L298) | [Line #316](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L316) | [Line #320](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L320) | [Line #334](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L334) | [Line #339](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L339) | [Line #351](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L351) | [Line #377](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L377) | [Line #391](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L391) | [Line #401](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L401) | [Line #413](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L413) | [Line #436](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L436) | [Line #443](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L443) | 
```solidity
File: contracts/StakedUSDe.sol

/// @audit Missed @param `from, to, uint256`
245: function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
/// @audit Missed @param `bytes32, address`
257: function renounceRole(bytes32, address) public virtual override {
```

| [Line #245](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L245) | [Line #257](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L257) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit Missed @param `assets, receiver, owner`
52: function withdraw(uint256 assets, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
/// @audit Missed @param `shares, receiver, owner`
65: function redeem(uint256 shares, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
```

| [Line #52](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L52) | [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L65) | 
```solidity
File: contracts/USDeSilo.sol

/// @audit Missed @param `stakingVault, usde`
18: constructor(address stakingVault, address usde) {
/// @audit Missed @param `to, amount`
28: function withdraw(address to, uint256 amount) external onlyStakingVault {
```

| [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L18) | [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L28) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

/// @audit Missed @param `role, account`
72: function _grantRole(bytes32 role, address account) internal override {
```

| [Line #72](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L72) | </details>


### [NC-44] Internal/Private State variable should have descriptions

Non-public state variables in smart contracts often have specialized purposes that may not be immediately clear to developers who did not write the original code.
Adding comments to explain the role and functionality of these variables can greatly aid in code readability and maintainability.
This is especially beneficial for future code reviews and audits.

<details>
<summary><i>4 issue instances in 2 files:</i></summary>

```solidity
File: contracts/USDeSilo.sol

15: address immutable STAKING_VAULT;
16: IERC20 immutable USDE;
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L15) | [Line #16](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L16) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

14: address private _currentDefaultAdmin;
15: address private _pendingDefaultAdmin;
```

| [Line #14](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L14) | [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L15) | </details>


### [NC-45] Modifiers Missing NatSpec `@param` Tag

Function modifiers should include NatSpec comments with `@param` tags describing each input parameter.
This promotes better code readability and documentation.

<details>
<summary><i>3 issue instances in 2 files:</i></summary>

```solidity
File: contracts/StakedUSDe.sol

/// @audit Missed @param `amount`
50: modifier notZero(uint256 amount) {
/// @audit Missed @param `target`
56: modifier notOwner(address target) {
```

| [Line #50](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L50) | [Line #56](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L56) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

/// @audit Missed @param `role`
17: modifier notAdmin(bytes32 role) {
```

| [Line #17](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L17) | </details>


### [NC-46] NatSpec: Public State variable declarations should have descriptions

State variables should ideally be accompanied by NatSpec comments to describe their purpose and usage. 
This aids developers in understanding the function and purpose of each variable, especially in large and complex contracts.
Consider adding `@dev` or `@notice` descriptions to your state variables.

<details>
<summary><i>5 issue instances in 2 files:</i></summary>

```solidity
File: contracts/USDe.sol

16: address public minter;
```

| [Line #16](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L16) | 
```solidity
File: contracts/StakedUSDeV2.sol

18: mapping(address => UserCooldown) public cooldowns;
20: USDeSilo public silo;
22: uint24 public MAX_COOLDOWN_DURATION = 90 days;
24: uint24 public cooldownDuration;
```

| [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L18) | [Line #20](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L20) | [Line #22](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L22) | [Line #24](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L24) | </details>


### [NC-47] Non-constant/non-immutable variables using all capital letters
Variable names that consist of all capital letters should be reserved for constant/immutable variables. If the variable needs to be different based on which class it comes from, a view/pure function should be used instead.
<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDeV2.sol

22: uint24 public MAX_COOLDOWN_DURATION = 90 days;
```

| [Line #22](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L22) | </details>


### [NC-48] Non-specific Imports

The current form of relative path import is not recommended for use because it can unpredictably pollute the namespace.
Instead, the Solidity docs recommend specifying imported symbols explicitly.
https://docs.soliditylang.org/en/v0.8.15/layout-of-source-files.html#importing-other-source-files

Example:
import {OwnableUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";

<details>
<summary><i>27 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

4: import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
5: import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
6: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
7: import "@openzeppelin/contracts/access/Ownable2Step.sol";
8: import "./interfaces/IUSDeDefinitions.sol";
```

| [Line #4](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L4) | [Line #5](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L5) | [Line #6](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L6) | [Line #7](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L7) | [Line #8](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L8) | 
```solidity
File: contracts/EthenaMinting.sol

8: import "./SingleAdminAccessControl.sol";
9: import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
10: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
11: import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
12: import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
14: import "./interfaces/IUSDe.sol";
15: import "./interfaces/IEthenaMinting.sol";
```

| [Line #8](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L8) | [Line #9](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L9) | [Line #10](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L10) | [Line #11](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L11) | [Line #12](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L12) | [Line #14](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L14) | [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L15) | 
```solidity
File: contracts/StakedUSDe.sol

8: import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
9: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
10: import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
11: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
12: import "./SingleAdminAccessControl.sol";
13: import "./interfaces/IStakedUSDe.sol";
```

| [Line #8](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L8) | [Line #9](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L9) | [Line #10](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L10) | [Line #11](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L11) | [Line #12](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L12) | [Line #13](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L13) | 
```solidity
File: contracts/StakedUSDeV2.sol

4: import "./StakedUSDe.sol";
5: import "./interfaces/IStakedUSDeCooldown.sol";
6: import "./USDeSilo.sol";
```

| [Line #4](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L4) | [Line #5](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L5) | [Line #6](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L6) | 
```solidity
File: contracts/USDeSilo.sol

4: import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
5: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
6: import "../contracts/interfaces/IUSDeSiloDefinitions.sol";
```

| [Line #4](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L4) | [Line #5](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L5) | [Line #6](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L6) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

4: import "@openzeppelin/contracts/access/AccessControl.sol";
5: import "@openzeppelin/contracts/interfaces/IERC5313.sol";
6: import "./interfaces/ISingleAdminAccessControl.sol";
```

| [Line #4](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L4) | [Line #5](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L5) | [Line #6](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L6) | </details>


### [NC-49] Explicit Visibility Recommended in Variable/Function Definitions

In Solidity, variable/function visibility is crucial for controlling access and protecting against unwanted modifications. 
While Solidity functions default to `internal` visibility, it is best practice to explicitly state the visibility for better code readability and avoiding confusion.

The missing visibility could lead to a false sense of security in contract design and potential vulnerabilities.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/USDeSilo.sol

15: address immutable STAKING_VAULT;
16: IERC20 immutable USDE;
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L15) | [Line #16](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L16) | </details>


### [NC-50] Outdated Solidity Version

The current Solidity version used in the contract is outdated.
Consider using a more recent version for improved features and security.

0.8.4: bytes.concat() instead of abi.encodePacked(,)

0.8.12: string.concat() instead of abi.encodePacked(,)

0.8.13: Ability to use using for with a list of free functions

0.8.14:
    ABI Encoder: When ABI-encoding values from calldata that contain nested arrays, correctly validate the nested array length against calldatasize() in all cases. Override Checker: Allow changing data location for parameters only when overriding external functions.

0.8.15:
    Code Generation: Avoid writing dirty bytes to storage when copying bytes arrays. Yul Optimizer: Keep all memory side-effects of inline assembly blocks.

0.8.16:
    Code Generation: Fix data corruption that affected ABI-encoding of calldata values represented by tuples: structs at any nesting level; argument lists of external functions, events and errors; return value lists of external functions. The 32 leading bytes of the first dynamically-encoded value in the tuple would get zeroed when the last component contained a statically-encoded array.

0.8.17:
    Yul Optimizer: Prevent the incorrect removal of storage writes before calls to Yul functions that conditionally terminate the external EVM call.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/USDeSilo.sol

2: pragma solidity ^0.8.0;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L2) | </details>


### [NC-51] Layout Order Does Not Comply with `Solidity Style Guide`

Adhering to a recommended order in Solidity contracts enhances code readability and maintenance.
[More information in Documentation](https://docs.soliditylang.org/en/latest/style-guide.html#order-of-layout)
It's recommended to use the following order:
1. Type declarations
2. State variables
3. Events
4. Errors
5. Modifiers
6. Functions

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/USDeSilo.sol

/// @audit `modifier` declared after `constructor`
22: modifier onlyStakingVault() {
```

| [Line #22](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L22) | </details>


### [NC-52] Unnecessary Use of `override` Keyword

In Solidity version 0.8.8 and later, the use of the `override` keyword becomes superfluous when a function is overriding solely from an interface and the function isn't present in multiple base contracts.
Previously, the `override` keyword was required as an explicit indication to the compiler. However, this is no longer the case, and the extraneous use of the keyword can make the code less clean and more verbose.

Solidity documentation on [Function Overriding](https://docs.soliditylang.org/en/v0.8.20/contracts.html#function-overriding).

<details>
<summary><i>19 issue instances in 5 files:</i></summary>

```solidity
File: contracts/USDe.sol

32: function renounceOwnership() public view override onlyOwner {
```

| [Line #32](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L32) | 
```solidity
File: contracts/EthenaMinting.sol

162: function mint(Order calldata order, Route calldata route, Signature calldata signature)
    external
    override
    nonReentrant
    onlyRole(MINTER_ROLE)
    belowMaxMintPerBlock(order.usde_amount)
  {
194: function redeem(Order calldata order, Signature calldata signature)
    external
    override
    nonReentrant
    onlyRole(REDEEMER_ROLE)
    belowMaxRedeemPerBlock(order.usde_amount)
  {
316: function hashOrder(Order calldata order) public view override returns (bytes32) {
339: function verifyOrder(Order calldata order, Signature calldata signature) public view override returns (bool, bytes32) {
351: function verifyRoute(Route calldata route, OrderType orderType) public view override returns (bool) {
377: function verifyNonce(address sender, uint256 nonce) public view override returns (bool, uint256, uint256, uint256) {
```

| [Line #162](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L162) | [Line #194](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L194) | [Line #316](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L316) | [Line #339](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L339) | [Line #351](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L351) | [Line #377](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L377) | 
```solidity
File: contracts/StakedUSDe.sol

166: function totalAssets() public view override returns (uint256) {
184: function decimals() public pure override(ERC4626, ERC20) returns (uint8) {
203: function _deposit(address caller, address receiver, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
  {
225: function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
  {
244: function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
257: function renounceRole(bytes32, address) public virtual override {
```

| [Line #166](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L166) | [Line #184](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L184) | [Line #203](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L203) | [Line #225](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L225) | [Line #244](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L244) | [Line #257](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L257) | 
```solidity
File: contracts/StakedUSDeV2.sol

52: function withdraw(uint256 assets, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
65: function redeem(uint256 shares, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
```

| [Line #52](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L52) | [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L65) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

41: function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
50: function revokeRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
58: function renounceRole(bytes32 role, address account) public virtual override notAdmin(role) {
72: function _grantRole(bytes32 role, address account) internal override {
```

| [Line #41](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L41) | [Line #50](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L50) | [Line #58](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L58) | [Line #72](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L72) | </details>


### [NC-53] Named Imports of Parent Contracts Are Missing

It's important to have named imports for parent contracts to ensure code readability and maintainability.
Missing named imports can make it difficult to understand the code hierarchy and can lead to issues in the future.

<details>
<summary><i>15 issue instances in 5 files:</i></summary>

```solidity
File: contracts/USDe.sol

/// @audit Missing named import for parent contract: `Ownable2Step`
15: contract USDe is Ownable2Step, ERC20Burnable, ERC20Permit, IUSDeDefinitions {
/// @audit Missing named import for parent contract: `ERC20Burnable`
15: contract USDe is Ownable2Step, ERC20Burnable, ERC20Permit, IUSDeDefinitions {
/// @audit Missing named import for parent contract: `ERC20Permit`
15: contract USDe is Ownable2Step, ERC20Burnable, ERC20Permit, IUSDeDefinitions {
/// @audit Missing named import for parent contract: `IUSDeDefinitions`
15: contract USDe is Ownable2Step, ERC20Burnable, ERC20Permit, IUSDeDefinitions {
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L15) | [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L15) | [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L15) | [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L15) | 
```solidity
File: contracts/EthenaMinting.sol

/// @audit Missing named import for parent contract: `IEthenaMinting`
21: contract EthenaMinting is IEthenaMinting, SingleAdminAccessControl, ReentrancyGuard {
/// @audit Missing named import for parent contract: `SingleAdminAccessControl`
21: contract EthenaMinting is IEthenaMinting, SingleAdminAccessControl, ReentrancyGuard {
/// @audit Missing named import for parent contract: `ReentrancyGuard`
21: contract EthenaMinting is IEthenaMinting, SingleAdminAccessControl, ReentrancyGuard {
```

| [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L21) | [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L21) | [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L21) | 
```solidity
File: contracts/StakedUSDe.sol

/// @audit Missing named import for parent contract: `SingleAdminAccessControl`
21: contract StakedUSDe is SingleAdminAccessControl, ReentrancyGuard, ERC20Permit, ERC4626, IStakedUSDe {
/// @audit Missing named import for parent contract: `ReentrancyGuard`
21: contract StakedUSDe is SingleAdminAccessControl, ReentrancyGuard, ERC20Permit, ERC4626, IStakedUSDe {
/// @audit Missing named import for parent contract: `ERC20Permit`
21: contract StakedUSDe is SingleAdminAccessControl, ReentrancyGuard, ERC20Permit, ERC4626, IStakedUSDe {
/// @audit Missing named import for parent contract: `ERC4626`
21: contract StakedUSDe is SingleAdminAccessControl, ReentrancyGuard, ERC20Permit, ERC4626, IStakedUSDe {
/// @audit Missing named import for parent contract: `IStakedUSDe`
21: contract StakedUSDe is SingleAdminAccessControl, ReentrancyGuard, ERC20Permit, ERC4626, IStakedUSDe {
```

| [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L21) | [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L21) | [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L21) | [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L21) | [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L21) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit Missing named import for parent contract: `IStakedUSDeCooldown`
15: contract StakedUSDeV2 is IStakedUSDeCooldown, StakedUSDe {
/// @audit Missing named import for parent contract: `StakedUSDe`
15: contract StakedUSDeV2 is IStakedUSDeCooldown, StakedUSDe {
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L15) | [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L15) | 
```solidity
File: contracts/USDeSilo.sol

/// @audit Missing named import for parent contract: `IUSDeSiloDefinitions`
12: contract USDeSilo is IUSDeSiloDefinitions {
```

| [Line #12](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L12) | </details>


### [NC-54] `public` functions not called by the contract should be declared `external` instead

Contracts are allowed to override their parents' functions and change the visibility from `external` to `public`.
If a `public` function is not called internally within the contract, it should be declared as `external` to save gas.

<details>
<summary><i>4 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

333: function encodeRoute(Route calldata route) public pure returns (bytes memory) {
```

| [Line #333](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L333) | 
```solidity
File: contracts/StakedUSDe.sol

166: function totalAssets() public view override returns (uint256) {
```

| [Line #166](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L166) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

41: function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
50: function revokeRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
```

| [Line #41](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L41) | [Line #50](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L50) | </details>


### [NC-55] Lack of Reentrancy Guards in Functions With Transfer Hooks

Functions that call contracts or addresses with transfer hooks should use reentrancy guards for protection. 
Even if these functions adhere to the check-effects-interaction best practice, absence of reentrancy guards can expose the protocol users to read-only reentrancies.
Without the guards, the only protective measure is to block-list the entire protocol, which isn't an optimal solution.

<details>
<summary><i>2 issue instances in 2 files:</i></summary>

```solidity
File: contracts/StakedUSDe.sol

/// @audit function `rescueTokens()` 
140: IERC20(token).safeTransfer(to, amount);
```

| [Line #140](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L140) | 
```solidity
File: contracts/USDeSilo.sol

/// @audit function `withdraw()` 
29: USDE.transfer(to, amount);
```

| [Line #29](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L29) | </details>


### [NC-56] Inclusive Language: Replace Sensitive Terms

Inclusive language plays a critical role in fostering an environment where everyone belongs.
Please use alternative terms as suggested below:
master -> source
slave -> replica
blacklist -> blocklist
whitelist -> allowlist

<details>
<summary><i>16 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDe.sol

27: /// @notice The role that is allowed to blacklist and un-blacklist addresses
28: bytes32 private constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
55: /// @notice ensures blacklist target is not owner
57: if (target == owner()) revert CantBlacklistOwner();
102: * @notice Allows the owner (DEFAULT_ADMIN_ROLE) and blacklist managers to blacklist addresses.
103: * @param target The address to blacklist.
104: * @param isFullBlacklisting Soft or full blacklisting level.
106: function addToBlacklist(address target, bool isFullBlacklisting)
108: onlyRole(BLACKLIST_MANAGER_ROLE)
111: bytes32 role = isFullBlacklisting ? FULL_RESTRICTED_STAKER_ROLE : SOFT_RESTRICTED_STAKER_ROLE;
116: * @notice Allows the owner (DEFAULT_ADMIN_ROLE) and blacklist managers to un-blacklist addresses.
117: * @param target The address to un-blacklist.
118: * @param isFullBlacklisting Soft or full blacklisting level.
120: function removeFromBlacklist(address target, bool isFullBlacklisting)
122: onlyRole(BLACKLIST_MANAGER_ROLE)
125: bytes32 role = isFullBlacklisting ? FULL_RESTRICTED_STAKER_ROLE : SOFT_RESTRICTED_STAKER_ROLE;
```

| [Line #27](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L27) | [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L28) | [Line #55](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L55) | [Line #57](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L57) | [Line #102](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L102) | [Line #103](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L103) | [Line #104](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L104) | [Line #106](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L106) | [Line #108](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L108) | [Line #111](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L111) | [Line #116](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L116) | [Line #117](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L117) | [Line #118](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L118) | [Line #120](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L120) | [Line #122](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L122) | [Line #125](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L125) | </details>


### [NC-57] Implement Value Comparison Checks in Setter Functions to Prevent Redundant State Updates

Setter functions should include a condition to check if the new value being assigned is different from the current value. This practice prevents redundant state changes and the emission of unnecessary events, ensuring that changes only occur when actual updates to the values are made.

This not only helps to maintain the integrity of the contract's state but also keeps the event logs cleaner and more meaningful by avoiding the recording of identical consecutive values. Such an approach can improve the clarity and efficiency of debugging and data tracking processes.

<details>
<summary><i>2 issue instances in 2 files:</i></summary>

```solidity
File: contracts/USDe.sol

/// @audit Missing `newMinter` check before state change
25: minter = newMinter;
```

| [Line #25](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L25) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit Missing `duration` check before state change
132: cooldownDuration = duration;
```

| [Line #132](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L132) | </details>


### [NC-58] Prefer Casting to `bytes` or `bytes32` Over `abi.encodePacked()` for Single Arguments

When using `abi.encodePacked()` on a single argument, it is often clearer to use a cast to `bytes` or `bytes32`.
This improves the semantic clarity of the code, making it easier for reviewers to understand the developer's intentions.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

49: bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(abi.encodePacked(EIP712_DOMAIN));
```

| [Line #49](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L49) | </details>


### [NC-59] Use Structs for Returning Multiple Variables

Functions that return many variables can become difficult to read and maintain.
Using a struct to encapsulate these return values can improve code readability, increase reusability, and reduce the likelihood of errors.
Consider refactoring functions that return more than three variables to use a struct instead.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

377: function verifyNonce(address sender, uint256 nonce) public view override returns (bool, uint256, uint256, uint256) {
```

| [Line #377](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L377) | </details>


### [NC-60] Use a single file for all system-wide constants

System-wide constants should be declared in a single file for better maintainability and readability.
This contract seems to contain constants which could potentially be system-wide and could be better managed if they were centralized in a single location.

<details>
<summary><i>15 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

28: bytes32 private constant EIP712_DOMAIN =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
32: bytes32 private constant ROUTE_TYPE = keccak256("Route(address[] addresses,uint256[] ratios)");
40: bytes32 private constant MINTER_ROLE = keccak256("MINTER_ROLE");
43: bytes32 private constant REDEEMER_ROLE = keccak256("REDEEMER_ROLE");
46: bytes32 private constant GATEKEEPER_ROLE = keccak256("GATEKEEPER_ROLE");
49: bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(abi.encodePacked(EIP712_DOMAIN));
52: address private constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
55: bytes32 private constant EIP_712_NAME = keccak256("EthenaMinting");
58: bytes32 private constant EIP712_REVISION = keccak256("1");
```

| [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L28) | [Line #32](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L32) | [Line #40](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L40) | [Line #43](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L43) | [Line #46](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L46) | [Line #49](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L49) | [Line #52](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L52) | [Line #55](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L55) | [Line #58](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L58) | 
```solidity
File: contracts/StakedUSDe.sol

26: bytes32 private constant REWARDER_ROLE = keccak256("REWARDER_ROLE");
28: bytes32 private constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
30: bytes32 private constant SOFT_RESTRICTED_STAKER_ROLE = keccak256("SOFT_RESTRICTED_STAKER_ROLE");
32: bytes32 private constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
34: uint256 private constant VESTING_PERIOD = 8 hours;
36: uint256 private constant MIN_SHARES = 1 ether;
```

| [Line #26](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L26) | [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L28) | [Line #30](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L30) | [Line #32](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L32) | [Line #34](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L34) | [Line #36](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L36) | </details>


### [NC-61] Missing event or timelock for critical parameter change

It is a good practice to give time for users to react and adjust to critical changes. A timelock provides more guarantees and reduces the level of trust required, thus decreasing risk for users. It also indicates that the project is legitimate (less risk of a malicious owner making a sandwich attack on a user).

<details>
<summary><i>5 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

219: function setMaxMintPerBlock(uint256 _maxMintPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {
224: function setMaxRedeemPerBlock(uint256 _maxRedeemPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {
```

| [Line #219](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L219) | [Line #224](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L224) | 
```solidity
File: contracts/StakedUSDeV2.sol

126: function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
```

| [Line #126](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L126) | </details>


### [NC-62] Consider Limit Input Array Length

The functions in question operate on arrays without established boundaries, executing function calls for each of their entries.
If these arrays become excessively long, a function might revert due to gas constraints.
To enhance user experience, consider incorporating a `require()` statement that enforces a sensible maximum array length.
This approach can avoid unnecessary computational work and ensure smoother transactions.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit `_custodians` is a function array parameter and `_custodians.length` is not bounded
130: for (uint256 j = 0; j < _custodians.length; j++) {
/// @audit `addresses` is a function array parameter and `addresses.length` is not bounded
424: for (uint256 i = 0; i < addresses.length; ++i) {
```

| [Line #130](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L130) | [Line #424](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L424) | </details>


### [NC-63] Presence of Unutilized Imports in the Contract

The contract contains import statements for libraries or other contracts that are not utilized within the code.
Excessive or unused imports can clutter the codebase, leading to inefficiency and potential confusion.
Consider removing any imports that are not essential to the contract's functionality.

<details>
<summary><i>2 issue instances in 2 files:</i></summary>

```solidity
File: contracts/USDe.sol

/// @audit - draft-ERC20Permit imported but not used
6: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
```

| [Line #6](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L6) | 
```solidity
File: contracts/StakedUSDe.sol

/// @audit - draft-ERC20Permit imported but not used
11: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
```

| [Line #11](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L11) | </details>


### [NC-64] Eliminate Unused Internal Functions for Code Clarity

This `internal` is not using in current scope, BUT it can be used in contracts that not in scope.

Unused `internal` functions within a contract can lead to confusion and clutter, making the code harder to understand and maintain.
Regularly reviewing and removing such unused functions is essential for maintaining a clean, readable, and robust codebase.
This practice ensures that developers and auditors can focus solely on the active parts of the contract, reducing the chances of oversight and potential errors.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDe.sol

/// @audit Internal `_deposit()` Function declared but never used
203: function _deposit(address caller, address receiver, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
  {
```

| [Line #203](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L203) | </details>


### [NC-65] Add Inline Comments for Unnamed Function Parameters

Having unnamed variables in function definitions can be confusing and decrease the code readability. 
Adding inline comments to explain the purpose of unnamed variables could make the code easier to understand and maintain.

For example, convert function declarations like `function foo(address x, address)` to `function foo(address x, address /* y */)` to indicate that the unnamed variable could have been named 'y'.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDe.sol

/// @audit - Add inline comments for unnamed variable `uint256` in function `_beforeTokenTransfer` for better readability.
244: function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
/// @audit - Add inline comments for unnamed variable `bytes32,address` in function `renounceRole` for better readability.
257: function renounceRole(bytes32, address) public virtual override {
```

| [Line #244](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L244) | [Line #257](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L257) | </details>


### [NC-66] Consider using `constant` instead of passing zero as a function argument

In instances where utilizing a zero parameter is essential, it is recommended to employ descriptive constants or an enum instead of directly integrating zero within function calls.
This strategy aids in clearly articulating the caller's intention and minimizes the risk of errors.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

230: _setMaxMintPerBlock(0);
231: _setMaxRedeemPerBlock(0);
```

| [Line #230](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L230) | [Line #231](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L231) | </details>


### [NC-67] `Solidity Style Guide`: Non-public Variable Names Without Leading Underscores

The naming convention for non-public (private and internal) variables in Solidity recommends the use of a leading underscore.

Since `constants` can be public, to avoid confusion, they should also be prefixed with an underscore.

This practice clearly differentiates between public/external and non-public variables, enhancing code clarity and reducing the likelihood of misinterpretation or errors.
Following this convention improves code readability and maintainability.

<details>
<summary><i>18 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

28: bytes32 private constant EIP712_DOMAIN =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
32: bytes32 private constant ROUTE_TYPE = keccak256("Route(address[] addresses,uint256[] ratios)");
35: bytes32 private constant ORDER_TYPE = keccak256(
    "Order(uint8 order_type,uint256 expiry,uint256 nonce,address benefactor,address beneficiary,address collateral_asset,uint256 collateral_amount,uint256 usde_amount)"
  );
40: bytes32 private constant MINTER_ROLE = keccak256("MINTER_ROLE");
43: bytes32 private constant REDEEMER_ROLE = keccak256("REDEEMER_ROLE");
46: bytes32 private constant GATEKEEPER_ROLE = keccak256("GATEKEEPER_ROLE");
49: bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(abi.encodePacked(EIP712_DOMAIN));
52: address private constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
55: bytes32 private constant EIP_712_NAME = keccak256("EthenaMinting");
58: bytes32 private constant EIP712_REVISION = keccak256("1");
```

| [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L28) | [Line #32](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L32) | [Line #35](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L35) | [Line #40](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L40) | [Line #43](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L43) | [Line #46](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L46) | [Line #49](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L49) | [Line #52](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L52) | [Line #55](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L55) | [Line #58](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L58) | 
```solidity
File: contracts/StakedUSDe.sol

26: bytes32 private constant REWARDER_ROLE = keccak256("REWARDER_ROLE");
28: bytes32 private constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
30: bytes32 private constant SOFT_RESTRICTED_STAKER_ROLE = keccak256("SOFT_RESTRICTED_STAKER_ROLE");
32: bytes32 private constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
34: uint256 private constant VESTING_PERIOD = 8 hours;
36: uint256 private constant MIN_SHARES = 1 ether;
```

| [Line #26](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L26) | [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L28) | [Line #30](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L30) | [Line #32](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L32) | [Line #34](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L34) | [Line #36](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L36) | 
```solidity
File: contracts/USDeSilo.sol

15: address immutable STAKING_VAULT;
16: IERC20 immutable USDE;
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L15) | [Line #16](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L16) | </details>


### [NC-68] Contracts should have full test coverage

It's recommended to have full test coverage for all contracts.
While 100% code coverage does not guarantee absence of bugs, it can catch simple bugs and reduce regressions during code modifications.
Moreover, to achieve full coverage, authors often have to refactor their code into more modular components, each testable separately.
This leads to lower interdependencies, and results in code that is easier to understand and audit.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: app/2023-10-ethena

1: All files
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/app/2023-10-ethena#L1) | </details>


### [NC-69] Insufficient Invariant Tests for Contracts

Large or complex code bases should include invariant fuzzing tests, such as those provided by Echidna.
These tests require the identification of invariants that should not be violated under any circumstances, with the fuzzer testing various inputs and function calls to ensure these invariants always hold.
This is especially important for code with a lot of inline-assembly, complicated math, or complex interactions between contracts. Despite having 100% code coverage, bugs can still occur due to the order of operations a user performs.
Extensive and well-written invariant tests can significantly reduce this testing gap.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: app/2023-10-ethena

1: All files
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/app/2023-10-ethena#L1) | </details>


### [NC-70] Implement Formal Verification Proofs to Improve Security

Formal verification offers a mathematical proof confirming that your code operates as intended and is devoid of edge cases 
that may lead to unintended behavior. By leveraging this rigorous audit technique, you not only enhance the robustness 
of your code but also strengthen the trust of stakeholders in the safety of your contract.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: app/2023-10-ethena

1: All files
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/app/2023-10-ethena#L1) | </details>


## Gas Findings Details

### [G-01] Optimize `<array>.length` Look-up in For-Loops

It is more efficient to cache the array length instead of looking it up in every iteration of a for-loop.

Example:

```solidity
- for(uint i = 0; i < array.length; i++)
+ uint length = array.length;
+ for(uint i = 0; i < length; i++);
```

<details>
<summary><i>4 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

126: for (uint256 i = 0; i < _assets.length; i++) {
130: for (uint256 j = 0; j < _custodians.length; j++) {
363: for (uint256 i = 0; i < route.addresses.length; ++i) {
424: for (uint256 i = 0; i < addresses.length; ++i) {
```

| [Line #126](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L126) | [Line #130](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L130) | [Line #363](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L363) | [Line #424](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L424) | </details>


### [G-02] Optimize Zero Checks Using Assembly

The usage of inline assembly to check if variable is the zero can save gas compared to traditional `require` or `if` statement checks. 

The assembly check uses the `extcodesize` operation which is generally cheaper in terms of gas.

[More information can be found here.](https://medium.com/@kalexotsu/solidity-assembly-checking-if-an-address-is-0-efficiently-d2bfe071331)

<details>
<summary><i>20 issue instances in 4 files:</i></summary>

```solidity
File: contracts/USDe.sol

19: if (admin == address(0)) revert ZeroAddressException();
```

| [Line #19](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L19) | 
```solidity
File: contracts/EthenaMinting.sol

119: if (address(_usde) == address(0)) revert InvalidUSDeAddress();
120: if (_assets.length == 0) revert NoAssetsProvided();
121: if (_admin == address(0)) revert InvalidZeroAddress();
248: if (wallet == address(0) || !_custodianAddresses.contains(wallet)) revert InvalidAddress();
291: if (asset == address(0) || asset == address(usde) || !_supportedAssets.add(asset)) {
      revert InvalidAssetAddress();
299: if (custodian == address(0) || custodian == address(usde) || !_custodianAddresses.add(custodian)) {
      revert InvalidCustodianAddress();
343: if (order.beneficiary == address(0)) revert InvalidAmount();
344: if (order.collateral_amount == 0) revert InvalidAmount();
345: if (order.usde_amount == 0) revert InvalidAmount();
360: if (route.addresses.length == 0) {
364: if (!_custodianAddresses.contains(route.addresses[i]) || route.addresses[i] == address(0) || route.ratios[i] == 0)
378: if (nonce == 0) revert InvalidNonce();
383: if (invalidator & invalidatorBit != 0) revert InvalidNonce();
```

| [Line #119](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L119) | [Line #120](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L120) | [Line #121](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L121) | [Line #248](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L248) | [Line #291](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L291) | [Line #299](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L299) | [Line #343](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L343) | [Line #344](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L344) | [Line #345](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L345) | [Line #360](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L360) | [Line #364](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L364) | [Line #378](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L378) | [Line #383](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L383) | 
```solidity
File: contracts/StakedUSDe.sol

51: if (amount == 0) revert InvalidAmount();
75: if (_owner == address(0) || _initialRewarder == address(0) || address(_asset) == address(0)) {
      revert InvalidZeroAddress();
153: if (to != address(0)) _mint(to, amountToDistribute);
246: if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
      revert OperationNotAllowed();
```

| [Line #51](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L51) | [Line #75](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L75) | [Line #153](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L153) | [Line #246](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L246) | 
```solidity
File: contracts/StakedUSDeV2.sol

28: if (cooldownDuration != 0) revert OperationNotAllowed();
34: if (cooldownDuration == 0) revert OperationNotAllowed();
```

| [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L28) | [Line #34](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L34) | </details>


### [G-03] Consider using `assembly` to write address storage values if the address variable is mutable

Writing address storage values using `assembly` can be more gas efficient when the address variable is mutable.
The following instances show mutable address storage variables that could be optimized using `assembly`.

<details>
<summary><i>3 issue instances in 2 files:</i></summary>

```solidity
File: contracts/USDe.sol

25: minter = newMinter;
```

| [Line #25](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L25) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

76: _currentDefaultAdmin = account;
27: _pendingDefaultAdmin = newAdmin;
```

| [Line #76](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L76) | [Line #27](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L27) | </details>


### [G-04] Unnecessary Stack Variable Cache for State Variables

If a state variable is only accessed once in a function, it's more gas-efficient to use the state variable directly.
This avoids the 3 gas overhead associated with the extra stack assignment.

<details>
<summary><i>3 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit `oldMaxMintPerBlock` is only used once, consider using the state variable directly.
437: uint256 oldMaxMintPerBlock = maxMintPerBlock;
/// @audit `oldMaxRedeemPerBlock` is only used once, consider using the state variable directly.
444: uint256 oldMaxRedeemPerBlock = maxRedeemPerBlock;
```

| [Line #437](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L437) | [Line #444](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L444) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit `previousDuration` is only used once, consider using the state variable directly.
131: uint24 previousDuration = cooldownDuration;
```

| [Line #131](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L131) | </details>


### [G-05] Consider Caching Multiple Accesses to Mappings/Arrays

Leveraging a local variable to cache these values when accessed more than once can yield a gas saving of approximately 42 units per access.
This reduction is attributed to eliminating the need for recalculating the key's keccak256 hash (which costs Gkeccak256 - 30 gas) and the associated stack operations.
For arrays, this also prevents the overhead of re-computing offsets in memory or calldata.

<details>
<summary><i>6 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDeV2.sol

/// @audit `cooldowns` is used more than once
100: cooldowns[owner].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
101: cooldowns[owner].underlyingAmount += assets;
/// @audit `cooldowns` is used more than once
116: cooldowns[owner].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
117: cooldowns[owner].underlyingAmount += assets;
```

| [Line #100](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L100) | [Line #101](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L101) | [Line #116](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L116) | [Line #117](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L117) | </details>


### [G-06] Use `unchecked {}` for division of `uint`s to save gas

Solidity introduced the `unchecked {}` block in version 0.8.0 as a measure to provide control over arithmetic operations. 
Any operation inside this block will not trigger the built-in overflow and underflow checks, thus saving gas costs. 
Since a division operation between two `uint`s (unsigned integers) can never result in an overflow or underflow, it's an ideal candidate for the use of `unchecked {}` block.
This practice enables optimal gas usage without risking any arithmetic anomalies.

<details>
<summary><i>2 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

425: uint256 amountToTransfer = (amount * ratios[i]) / 10_000;
```

| [Line #425](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L425) | 
```solidity
File: contracts/StakedUSDe.sol

180: return ((VESTING_PERIOD - timeSinceLastDistribution) * vestingAmount) / VESTING_PERIOD;
```

| [Line #180](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L180) | </details>


### [G-07] Optimize Gas by Using Do-While Loops

Using `do-while` loops instead of `for` loops can be more gas-efficient. 
Even if you add an `if` condition to account for the case where the loop doesn't execute at all, a `do-while` loop can still be cheaper in terms of gas.

Example:
```solidity
/// 774 gas cost
function forLoop() public pure {
    for (uint256 i; i < 10;) {
        unchecked {
            ++i;
        }
    }
}
/// 519 gas cost
function doWhileLoop() public pure {
    uint256 i;
    do {
        unchecked {
            ++i;
        }
    } while (i < 10);
}
```

<details>
<summary><i>4 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

125: for (uint256 i = 0; i < _assets.length; i++) {
129: for (uint256 j = 0; j < _custodians.length; j++) {
363: for (uint256 i = 0; i < route.addresses.length; ++i) {
424: for (uint256 i = 0; i < addresses.length; ++i) {
```

| [Line #125](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L125) | [Line #129](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L129) | [Line #363](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L363) | [Line #424](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L424) | </details>


### [G-08] Use Assembly for Efficient Event Emission

To efficiently emit events, consider utilizing assembly by making use of scratch space and the free memory pointer.
This approach can potentially avoid the costs associated with memory expansion.

However, it's crucial to cache and restore the free memory pointer for safe optimization.
Good examples of such practices can be found in well-optimized [Solady's codebases](https://github.com/Vectorized/solady/blob/main/src/tokens/ERC1155.sol#L167).
Please review your code and consider the potential gas savings of this approach.

<details>
<summary><i>19 issue instances in 5 files:</i></summary>

```solidity
File: contracts/USDe.sol

24: emit MinterUpdated(newMinter, minter);
```

| [Line #24](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L24) | 
```solidity
File: contracts/EthenaMinting.sol

145: emit USDeSet(address(_usde));
154: emit Received(msg.sender, msg.value);
179: emit Mint(
      msg.sender,
      order.benefactor,
      order.beneficiary,
      order.collateral_asset,
      order.collateral_amount,
      order.usde_amount
    );
208: emit Redeem(
      msg.sender,
      order.benefactor,
      order.beneficiary,
      order.collateral_asset,
      order.collateral_amount,
      order.usde_amount
    );
237: emit DelegatedSignerAdded(_delegateTo, msg.sender);
243: emit DelegatedSignerRemoved(_removedSigner, msg.sender);
255: emit CustodyTransfer(wallet, asset, amount);
261: emit AssetRemoved(asset);
272: emit CustodianAddressRemoved(custodian);
294: emit AssetAdded(asset);
302: emit CustodianAddressAdded(custodian);
439: emit MaxMintPerBlockChanged(oldMaxMintPerBlock, maxMintPerBlock);
446: emit MaxRedeemPerBlockChanged(oldMaxRedeemPerBlock, maxRedeemPerBlock);
```

| [Line #145](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L145) | [Line #154](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L154) | [Line #179](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L179) | [Line #208](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L208) | [Line #237](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L237) | [Line #243](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L243) | [Line #255](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L255) | [Line #261](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L261) | [Line #272](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L272) | [Line #294](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L294) | [Line #302](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L302) | [Line #439](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L439) | [Line #446](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L446) | 
```solidity
File: contracts/StakedUSDe.sol

98: emit RewardsReceived(amount, newVestingAmount);
155: emit LockedAmountRedistributed(from, to, amountToDistribute);
```

| [Line #98](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L98) | [Line #155](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L155) | 
```solidity
File: contracts/StakedUSDeV2.sol

133: emit CooldownDurationUpdated(previousDuration, cooldownDuration);
```

| [Line #133](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L133) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

28: emit AdminTransferRequested(_currentDefaultAdmin, newAdmin);
74: emit AdminTransferred(_currentDefaultAdmin, account);
```

| [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L28) | [Line #74](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L74) | </details>


### [G-09] Enable `--via-ir` for Potential Gas Savings Through Cross-Function Optimizations

The `--via-ir` command line option activates the IR-based code generator in Solidity, which is designed to enable powerful optimization passes that can span across functions. The end result may be a contract that requires less gas to execute its functions.

We recommend you enable this feature, run tests, and benchmark the gas usage of your contract to evaluate if it leads to any tangible gas savings. Experimenting with this feature could lead to a more gas-efficient contract.

[Solidity Documentation](https://docs.soliditylang.org/en/v0.8.20/ir-breaking-changes.html#solidity-ir-based-codegen-changes).

<details>
<summary><i>6 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

```
</details>


### [G-10] Optimize External Calls with Assembly for Memory Efficiency

Using interfaces to make external contract calls in Solidity is convenient but can be inefficient in terms of memory utilization.
Each such call involves creating a new memory location to store the data being passed, thus incurring memory expansion costs. 

Inline assembly allows for optimized memory usage by re-using already allocated memory spaces or using the scratch space for smaller datasets.
This can result in notable gas savings, especially for contracts that make frequent external calls.

Additionally, using inline assembly enables important safety checks like verifying if the target address has code deployed to it using `extcodesize(addr)` before making the call, mitigating risks associated with contract interactions.

<details>
<summary><i>7 issue instances in 4 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

178: usde.mint(order.beneficiary, order.usde_amount);
206: usde.burnFrom(order.benefactor, order.usde_amount);
253: IERC20(asset).safeTransfer(wallet, amount);
408: IERC20(asset).safeTransfer(beneficiary, amount);
```

| [Line #178](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L178) | [Line #206](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L206) | [Line #253](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L253) | [Line #408](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L408) | 
```solidity
File: contracts/StakedUSDe.sol

140: IERC20(token).safeTransfer(to, amount);
```

| [Line #140](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L140) | 
```solidity
File: contracts/StakedUSDeV2.sol

86: silo.withdraw(receiver, assets);
```

| [Line #86](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L86) | 
```solidity
File: contracts/USDeSilo.sol

29: USDE.transfer(to, amount);
```

| [Line #29](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L29) | </details>


### [G-11] Consider Using `>=`/`<=` Instead of `>`/`<`

The Solidity compiler requires fewer opcodes when the `>=` operator is used in place of the `>` operator. 
Specifically, the compiler uses GT and ISZERO opcodes for `>` but only requires LT for `>=`, saving 3 gas. 
Thus, wherever applicable, it's recommended to use `>=` instead of `>` to enhance gas efficiency in your code. Same applies for `<=` and `<`.

<details>
<summary><i>12 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

98: if (mintedPerBlock[block.number] + mintAmount > maxMintPerBlock) revert MaxMintPerBlockExceeded();
105: if (redeemedPerBlock[block.number] + redeemAmount > maxRedeemPerBlock) revert MaxRedeemPerBlockExceeded();
126: for (uint256 i = 0; i < _assets.length; i++) {
130: for (uint256 j = 0; j < _custodians.length; j++) {
346: if (block.timestamp > order.expiry) revert SignatureExpired();
363: for (uint256 i = 0; i < route.addresses.length; ++i) {
403: if (address(this).balance < amount) revert InvalidAmount();
424: for (uint256 i = 0; i < addresses.length; ++i) {
```

| [Line #98](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L98) | [Line #105](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L105) | [Line #126](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L126) | [Line #130](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L130) | [Line #346](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L346) | [Line #363](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L363) | [Line #403](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L403) | [Line #424](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L424) | 
```solidity
File: contracts/StakedUSDe.sol

193: if (_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();
```

| [Line #193](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L193) | 
```solidity
File: contracts/StakedUSDeV2.sol

96: if (assets > maxWithdraw(owner)) revert ExcessiveWithdrawAmount();
112: if (shares > maxRedeem(owner)) revert ExcessiveRedeemAmount();
127: if (duration > MAX_COOLDOWN_DURATION) {
```

| [Line #96](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L96) | [Line #112](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L112) | [Line #127](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L127) | </details>


### [G-12] Use Assembly for Hash Calculations

In certain cases, using inline assembly to calculate hashes can lead to significant gas savings. Solidity's built-in keccak256 function is convenient but costs more gas than the equivalent assembly code. However, it's important to note that using assembly should be done with care as it's less readable and could increase the risk of introducing errors.

<details>
<summary><i>3 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

29: keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
317: return ECDSA.toTypedDataHash(getDomainSeparator(), keccak256(encodeOrder(order)));
452: return keccak256(abi.encode(EIP712_DOMAIN, EIP_712_NAME, EIP712_REVISION, block.chainid, address(this)));
```

| [Line #29](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L29) | [Line #317](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L317) | [Line #452](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L452) | </details>


### [G-13] Inline `internal` Functions That Called Once

`internal` functions that are only called once should be inlined to save gas. 
Not inlining such functions costs an extra 20 to 40 gas due to the additional `JUMP` instructions and stack operations required for function calls.

<details>
<summary><i>4 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

401: function _transferToBeneficiary(address beneficiary, address asset, uint256 amount) internal {
// This function called only once.
413: function _transferCollateral(
    uint256 amount,
    address asset,
    address benefactor,
    address[] calldata addresses,
    uint256[] calldata ratios
  ) internal {
// This function called only once.
```

| [Line #401](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L401) | [Line #413](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L413) | 
```solidity
File: contracts/StakedUSDe.sol

203: function _deposit(address caller, address receiver, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
  {
// This function called only once.
225: function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
  {
// This function called only once.
```

| [Line #203](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L203) | [Line #225](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L225) | </details>


### [G-14] Optimize Gas Spend Using `0.8.20` and Optimizer Features

New features introduced in Solidity 0.8.20 that enhance gas efficiency.
Specifically, it takes advantage of the `push0` assembler operation for placing 0 on the EVM stack, which reduces both deployment and runtime costs.

Furthermore, it utilizes the re-implemented versions of the `UnusedAssignEliminator` and `UnusedStoreEliminator` in the Solidity optimizer, eliminating unused assignments in deeply nested loops and thus further reducing the gas required for contract execution.

<details>
<summary><i>6 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

2: pragma solidity 0.8.19;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L2) | 
```solidity
File: contracts/EthenaMinting.sol

2: pragma solidity 0.8.19;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L2) | 
```solidity
File: contracts/StakedUSDe.sol

2: pragma solidity 0.8.19;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L2) | 
```solidity
File: contracts/StakedUSDeV2.sol

2: pragma solidity 0.8.19;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L2) | 
```solidity
File: contracts/USDeSilo.sol

2: pragma solidity ^0.8.0;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L2) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

2: pragma solidity 0.8.19;
```

| [Line #2](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L2) | </details>


### [G-15] Consider Using Solady's Gas Optimized Lib for Math

Utilizing gas-optimized math functions from libraries like [Solady](https://github.com/Vectorized/solady/blob/main/src/utils/FixedPointMathLib.sol) can lead to more efficient smart contracts.
This is particularly beneficial in contracts where these operations are frequently used.

<details>
<summary><i>4 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

425: uint256 amountToTransfer = (amount * ratios[i]) / 10_000;
425: uint256 amountToTransfer = (amount * ratios[i]) / 10_000;
```

| [Line #425](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L425) | [Line #425](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L425) | 
```solidity
File: contracts/StakedUSDe.sol

180: return ((VESTING_PERIOD - timeSinceLastDistribution) * vestingAmount) / VESTING_PERIOD;
180: return ((VESTING_PERIOD - timeSinceLastDistribution) * vestingAmount) / VESTING_PERIOD;
```

| [Line #180](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L180) | [Line #180](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L180) | </details>


### [G-16] Trade-offs Between Modifiers and Internal Functions

In Solidity, both internal functions and modifiers are used to refactor and manage code, but they come with their own trade-offs, especially in terms of gas cost and flexibility.

#### Modifiers:
  - Less runtime gas cost (saves around 24 gas per function call).
  - Increases deployment gas cost due to repetitive code.
  - Can only be executed at the start or end of a function.

#### Internal Functions:
  - Lower deployment cost.
  - Can be executed at any point in a function.
  - Slightly higher runtime gas cost (24 gas) due to the need to jump to the function's location in bytecode.

#### Recommendations:
- Use modifiers for high-frequency functions where runtime gas cost matters the most.
- Use internal functions where the priority is reducing deployment gas cost or when you need more flexibility in the function's logic.

Example analysis shows that using modifiers can increase deployment costs by over 35k gas but save 24 gas per function call during runtime. Choose wisely based on your specific use case.

<details>
<summary><i>23 issue instances in 5 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

97: modifier belowMaxMintPerBlock(uint256 mintAmount) {
162: function mint(Order calldata order, Route calldata route, Signature calldata signature)
    external
    override
    nonReentrant
    onlyRole(MINTER_ROLE)
    belowMaxMintPerBlock(order.usde_amount)
  {
104: modifier belowMaxRedeemPerBlock(uint256 redeemAmount) {
194: function redeem(Order calldata order, Signature calldata signature)
    external
    override
    nonReentrant
    onlyRole(REDEEMER_ROLE)
    belowMaxRedeemPerBlock(order.usde_amount)
  {
```

| [Line #97](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L97) | [Line #162](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L162) | [Line #104](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L104) | [Line #194](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L194) | 
```solidity
File: contracts/StakedUSDe.sol

50: modifier notZero(uint256 amount) {
89: function transferInRewards(uint256 amount) external nonReentrant onlyRole(REWARDER_ROLE) notZero(amount) {
203: function _deposit(address caller, address receiver, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
  {
225: function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
  {
56: modifier notOwner(address target) {
106: function addToBlacklist(address target, bool isFullBlacklisting)
    external
    onlyRole(BLACKLIST_MANAGER_ROLE)
    notOwner(target)
  {
120: function removeFromBlacklist(address target, bool isFullBlacklisting)
    external
    onlyRole(BLACKLIST_MANAGER_ROLE)
    notOwner(target)
  {
```

| [Line #50](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L50) | [Line #89](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L89) | [Line #203](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L203) | [Line #225](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L225) | [Line #56](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L56) | [Line #106](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L106) | [Line #120](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L120) | 
```solidity
File: contracts/StakedUSDeV2.sol

27: modifier ensureCooldownOff() {
52: function withdraw(uint256 assets, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
65: function redeem(uint256 shares, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
33: modifier ensureCooldownOn() {
95: function cooldownAssets(uint256 assets, address owner) external ensureCooldownOn returns (uint256) {
111: function cooldownShares(uint256 shares, address owner) external ensureCooldownOn returns (uint256) {
```

| [Line #27](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L27) | [Line #52](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L52) | [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L65) | [Line #33](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L33) | [Line #95](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L95) | [Line #111](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L111) | 
```solidity
File: contracts/USDeSilo.sol

22: modifier onlyStakingVault() {
27: function withdraw(address to, uint256 amount) external onlyStakingVault {
```

| [Line #22](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L22) | [Line #27](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L27) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

16: modifier notAdmin(bytes32 role) {
41: function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
50: function revokeRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
58: function renounceRole(bytes32 role, address account) public virtual override notAdmin(role) {
```

| [Line #16](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L16) | [Line #41](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L41) | [Line #50](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L50) | [Line #58](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L58) | </details>


### [G-17] Avoid Using `_msgSender()` if not Supporting EIP-2771

From a gas efficiency perspective, using `_msgSender()` in a contract not intended to support EIP-2771 could add unnecessary overhead. The _msgSender() function includes checks to determine if the transaction was forwarded, which involves extra function calls that consume more gas than a simple msg.sender.

If a contract doesn't require EIP-2771 meta-transaction support, using msg.sender directly is more gas efficient. msg.sender is a globally accessible variable in Solidity that doesn't require an extra function call, making it a less costly choice.

In the context of Ethereum, where every operation has a gas cost, it's crucial to eliminate unnecessary computations to optimize contract execution and minimize transaction fees. Therefore, if EIP-2771 support isn't necessary, it's recommended to use msg.sender instead of _msgSender().

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDeV2.sol

103: _withdraw(_msgSender(), address(silo), owner, assets, shares);
119: _withdraw(_msgSender(), address(silo), owner, assets, shares);
```

| [Line #103](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L103) | [Line #119](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L119) | </details>


### [G-18] Optimize Gas Usage by Combining Mappings into a Struct

Combining multiple address/ID mappings into a single mapping to a struct can lead to gas savings.
By refactoring multiple mappings into a singular mapping with a struct, you can save on storage slots, which in turn can reduce the gas cost in certain operations.
Prioritize this refactor if optimizing gas is a primary concern for your contract's operations.

<details>
<summary><i>4 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

78: mapping(address => mapping(uint256 => uint256)) private _orderBitmaps;
86: mapping(address => mapping(address => bool)) public delegatedSigner;
81: mapping(uint256 => uint256) public mintedPerBlock;
83: mapping(uint256 => uint256) public redeemedPerBlock;
```

| [Line #78](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L78) | [Line #86](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L86) | [Line #81](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L81) | [Line #83](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L83) | </details>


### [G-19] Using nested `if` save gas

Optimization of condition checks in your smart contract is a crucial aspect in ensuring gas efficiency. Specifically, substituting multiple `&&` checks with nested `if` statements can lead to substantial gas savings.

When evaluating multiple conditions within a single `if` statement using the `&&` operator, each condition will consume gas even if a preceding condition fails. However, if these checks are broken down into nested `if` statements, execution halts as soon as a condition fails, saving the gas that would have been consumed by subsequent checks.

This practice is especially beneficial in scenarios where the `if` statement isn't followed by an `else` statement. The reason being, when an `else` statement is present, all conditions must be checked regardless to determine the correct branch of execution.

By reworking your code to utilize nested `if` statements, you can optimize gas usage, reduce execution cost, and enhance your contract's performance.

<details>
<summary><i>3 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDe.sol

149: if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && !hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
193: if (_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();
246: if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
```

| [Line #149](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L149) | [Line #193](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L193) | [Line #246](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L246) | </details>


### [G-20] Avoid Zero to Non-Zero Storage Writes Where Possible

Changing a storage variable from zero to non-zero costs 22,100 gas in total. (20,000 gas for a zero to non-zero write and 2,100 for a cold storage access)
Consider using non-zero architecture to avoid high gas costs for zero to non-zero storage writes.

Example:

```solidity
- uint256 public counter = 0;  // rewrite this costs more
+ uint256 public counter = 1;  // rewrite this costs less
```

<details>
<summary><i>5 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

438: maxMintPerBlock = _maxMintPerBlock;
445: maxRedeemPerBlock = _maxRedeemPerBlock;
```

| [Line #438](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L438) | [Line #445](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L445) | 
```solidity
File: contracts/StakedUSDe.sol

93: vestingAmount = newVestingAmount;
94: lastDistributionTimestamp = block.timestamp;
```

| [Line #93](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L93) | [Line #94](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L94) | 
```solidity
File: contracts/StakedUSDeV2.sol

132: cooldownDuration = duration;
```

| [Line #132](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L132) | </details>


### [G-21] Optimize Deployment Size by Fine-tuning IPFS Hash

The Solidity compiler appends 53 bytes of metadata to the smart contract code which translates to an extra 10,600 gas (200 per bytecode) + the calldata cost (16 gas per non-zero bytes, 4 gas per zero-byte).
This translates to up to 848 additional gas in calldata cost.
One way to reduce this cost is by optimizing the IPFS hash that gets appended to the smart contract code.

Why is this important?
- The metadata adds an extra 53 bytes, resulting in an additional 10,600 gas cost for deployment.
- It also incurs up to 848 additional gas in calldata cost.

Options to Reduce Gas:
1. Use the `--no-cbor-metadata` compiler option to exclude metadata, but this might affect contract verification.
2. Mine for code comments that lead to an IPFS hash with more zeros, reducing calldata costs.


<details>
<summary><i>6 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

1: Consider optimizing the IPFS hash during deployment.
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L1) | 
```solidity
File: contracts/EthenaMinting.sol

1: Consider optimizing the IPFS hash during deployment.
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L1) | 
```solidity
File: contracts/StakedUSDe.sol

1: Consider optimizing the IPFS hash during deployment.
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L1) | 
```solidity
File: contracts/StakedUSDeV2.sol

1: Consider optimizing the IPFS hash during deployment.
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L1) | 
```solidity
File: contracts/USDeSilo.sol

1: Consider optimizing the IPFS hash during deployment.
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L1) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

1: Consider optimizing the IPFS hash during deployment.
```

| [Line #1](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L1) | </details>


### [G-22] Optimize Function Names for Gas Savings

Function names for public and external methods, as well as public state variable names, can be optimized to achieve gas savings.
By renaming functions to generate method IDs with two leading zero bytes, you can save 128 gas during contract deployment.
Further, renaming functions for lower method IDs can conserve 22 gas per call for each sorted position shifted.

Optimizing function names for gas efficiency can result in significant savings, especially for frequently called functions or heavily deployed contracts. 
Reference: [Solidity Gas Optimizations - Function Name](https://blog.emn178.cc/en/post/solidity-gas-optimization-function-name/)

<details>
<summary><i>6 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

15: contract USDe is Ownable2Step, ERC20Burnable, ERC20Permit, IUSDeDefinitions {
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L15) | 
```solidity
File: contracts/EthenaMinting.sol

21: contract EthenaMinting is IEthenaMinting, SingleAdminAccessControl, ReentrancyGuard {
```

| [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L21) | 
```solidity
File: contracts/StakedUSDe.sol

21: contract StakedUSDe is SingleAdminAccessControl, ReentrancyGuard, ERC20Permit, ERC4626, IStakedUSDe {
```

| [Line #21](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L21) | 
```solidity
File: contracts/StakedUSDeV2.sol

15: contract StakedUSDeV2 is IStakedUSDeCooldown, StakedUSDe {
```

| [Line #15](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L15) | 
```solidity
File: contracts/USDeSilo.sol

12: contract USDeSilo is IUSDeSiloDefinitions {
```

| [Line #12](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L12) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

13: abstract contract SingleAdminAccessControl is IERC5313, ISingleAdminAccessControl, AccessControl {
```

| [Line #13](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L13) | </details>


### [G-23] Using bools for storage incurs overhead

Utilizing booleans for storage is less gas-efficient compared to using types that consume a full word like uint256.
Every write operation on a boolean necessitates an extra SLOAD operation to read the slot's current value, modify the boolean bits, and then write back.
This additional step is the compiler's measure against contract upgrades and pointer aliasing.

To enhance gas efficiency, consider using `uint256(0)` for false and `uint256(1)` for true, bypassing the extra Gwarmaccess (100 gas) incurred by the SLOAD.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

86: mapping(address => mapping(address => bool)) public delegatedSigner;
```

| [Line #86](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L86) | </details>


### [G-24] Optimize Boolean States with `uint256(1/2)`

Boolean variables in Solidity are more expensive than `uint256` or any type that takes up a full word, due to additional gas costs associated with write operations.
When using boolean variables, each write operation emits an extra SLOAD to read the slot's contents, replace the bits taken up by the boolean, and then write back.
This process cannot be disabled and leads to extra gas consumption.

By using `uint256(1)` and `uint256(2)` for representing true and false states, you can avoid a `Gwarmaccess` (100 gas) cost and also avoid a `Gsset` (20000 gas) cost when changing from `false` to `true`, after having been `true` in the past.
This approach helps in optimizing gas usage, making your contract more cost-effective.

[Usage in OpenZeppelin ReentrancyGuard.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27)

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

86: mapping(address => mapping(address => bool)) public delegatedSigner;
```

| [Line #86](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L86) | </details>


### [G-25] Consider Packing Small `uint` When it's Possible

Packing `uint` variables into the same storage slot can help in reducing gas costs.
This is particularly useful when storing or reading multiple smaller uints (e.g., uint80) in a single transaction.
Consider using bit manipulation to pack these variables.

If you pack two `uint` variables into a single `uint` storage slot, you'd perform only one SLOAD operation (800 gas) instead of two (1,600 gas) when you read them.
This saves 800 gas for each read operation involving the two variables.

Similarly, when you need to update both variables, a single SSTORE operation would cost you 20,000 gas instead of 40,000 gas, saving you another 20,000 gas. 

Example:
```Solidity
uint160 packedVariables;

function packVariables(uint80 x, uint80 y) external {
    packedVariables = uint160(x) << 80 | uint160(y);
}
```

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDeV2.sol

22: uint24 public MAX_COOLDOWN_DURATION = 90 days;
24: uint24 public cooldownDuration;
```

| [Line #22](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L22) | [Line #24](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L24) | </details>


### [G-26] Consider Marking Constructors As `payable`

Payable functions cost less gas to execute, since the compiler does not have to add extra checks to ensure that a payment wasn't provided.

A constructor can safely be marked as `payable`, since only the deployer would be able to pass funds, and the project itself would not pass any funds. 
T
his could save an average of about 21 gas per call, in addition to the extra deployment cost.

<details>
<summary><i>5 issue instances in 5 files:</i></summary>

```solidity
File: contracts/USDe.sol

17: constructor(address admin) ERC20("USDe", "USDe") ERC20Permit("USDe") {
```

| [Line #17](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L17) | 
```solidity
File: contracts/EthenaMinting.sol

110: constructor(
    IUSDe _usde,
    address[] memory _assets,
    address[] memory _custodians,
    address _admin,
    uint256 _maxMintPerBlock,
    uint256 _maxRedeemPerBlock
  ) {
```

| [Line #110](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L110) | 
```solidity
File: contracts/StakedUSDe.sol

70: constructor(IERC20 _asset, address _initialRewarder, address _owner)
    ERC20("Staked USDe", "stUSDe")
    ERC4626(_asset)
    ERC20Permit("stUSDe")
  {
```

| [Line #70](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L70) | 
```solidity
File: contracts/StakedUSDeV2.sol

42: constructor(IERC20 _asset, address initialRewarder, address owner) StakedUSDe(_asset, initialRewarder, owner) {
```

| [Line #42](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L42) | 
```solidity
File: contracts/USDeSilo.sol

17: constructor(address stakingVault, address usde) {
```

| [Line #17](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L17) | </details>


### [G-27] Mark Functions That Revert For Normal Users As `payable`

Functions guaranteed to revert when called by normal users can be marked `payable`.
If a function modifier such as onlyOwner is used, the function will revert if a normal user tries to pay the function.
Marking the function as payable will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.

The extra opcodes avoided are CALLVALUE(2),DUP1(3),ISZERO(3),PUSH2(3),JUMPI(10),PUSH1(3),DUP1(3),REVERT(0),JUMPDEST(1),POP(2), which costs an average of about 21 gas per call to the function, in addition to the extra deployment cost.

<details>
<summary><i>24 issue instances in 6 files:</i></summary>

```solidity
File: contracts/USDe.sol

22: function setMinter(address newMinter) external onlyOwner {
32: function renounceOwnership() public view override onlyOwner {
```

| [Line #22](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L22) | [Line #32](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L32) | 
```solidity
File: contracts/EthenaMinting.sol

162: function mint(Order calldata order, Route calldata route, Signature calldata signature)
    external
    override
    nonReentrant
    onlyRole(MINTER_ROLE)
    belowMaxMintPerBlock(order.usde_amount)
  {
194: function redeem(Order calldata order, Signature calldata signature)
    external
    override
    nonReentrant
    onlyRole(REDEEMER_ROLE)
    belowMaxRedeemPerBlock(order.usde_amount)
  {
219: function setMaxMintPerBlock(uint256 _maxMintPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {
224: function setMaxRedeemPerBlock(uint256 _maxRedeemPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {
229: function disableMintRedeem() external onlyRole(GATEKEEPER_ROLE) {
247: function transferToCustody(address wallet, address asset, uint256 amount) external nonReentrant onlyRole(MINTER_ROLE) {
259: function removeSupportedAsset(address asset) external onlyRole(DEFAULT_ADMIN_ROLE) {
270: function removeCustodianAddress(address custodian) external onlyRole(DEFAULT_ADMIN_ROLE) {
277: function removeMinterRole(address minter) external onlyRole(GATEKEEPER_ROLE) {
283: function removeRedeemerRole(address redeemer) external onlyRole(GATEKEEPER_ROLE) {
290: function addSupportedAsset(address asset) public onlyRole(DEFAULT_ADMIN_ROLE) {
298: function addCustodianAddress(address custodian) public onlyRole(DEFAULT_ADMIN_ROLE) {
```

| [Line #162](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L162) | [Line #194](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L194) | [Line #219](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L219) | [Line #224](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L224) | [Line #229](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L229) | [Line #247](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L247) | [Line #259](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L259) | [Line #270](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L270) | [Line #277](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L277) | [Line #283](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L283) | [Line #290](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L290) | [Line #298](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L298) | 
```solidity
File: contracts/StakedUSDe.sol

89: function transferInRewards(uint256 amount) external nonReentrant onlyRole(REWARDER_ROLE) notZero(amount) {
106: function addToBlacklist(address target, bool isFullBlacklisting)
    external
    onlyRole(BLACKLIST_MANAGER_ROLE)
    notOwner(target)
  {
120: function removeFromBlacklist(address target, bool isFullBlacklisting)
    external
    onlyRole(BLACKLIST_MANAGER_ROLE)
    notOwner(target)
  {
138: function rescueTokens(address token, uint256 amount, address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
148: function redistributeLockedAmount(address from, address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
```

| [Line #89](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L89) | [Line #106](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L106) | [Line #120](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L120) | [Line #138](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L138) | [Line #148](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L148) | 
```solidity
File: contracts/StakedUSDeV2.sol

126: function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
```

| [Line #126](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L126) | 
```solidity
File: contracts/USDeSilo.sol

27: function withdraw(address to, uint256 amount) external onlyStakingVault {
```

| [Line #27](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L27) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

25: function transferAdmin(address newAdmin) external onlyRole(DEFAULT_ADMIN_ROLE) {
41: function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
50: function revokeRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
```

| [Line #25](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L25) | [Line #41](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L41) | [Line #50](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L50) | </details>


### [G-28] Use Pre-Increment/Decrement (++i/--i) to Save Gas

Using pre-increment (++i) or pre-decrement (--i) operators is more gas-efficient compared to their post counterparts (i++ or i--).
This is because pre-increment/decrement operators avoid the need for an additional temporary variable that stores the original value of the iterator.
This subtle difference results in saving of around 5 gas units per operation, which can accumulate to substantial savings in gas costs in contracts with frequent increment/decrement operations.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

126: for (uint256 i = 0; i < _assets.length; i++) {
130: for (uint256 j = 0; j < _custodians.length; j++) {
```

| [Line #126](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L126) | [Line #130](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L130) | </details>


### [G-29] Avoid Unnecessary Public Variables

Public storage variables increase the contract's size due to the implicit generation of public getter functions. 
This makes the contract larger and could increase deployment and interaction costs.

If you do not require other contracts to read these variables, consider making them `private` or `internal`. 

Example:
```solidity
/// 145426 gas to deploy
contract PublicState {
    address public first;
    address public second;
}
/// 77126 gas to deploy
contract PrivateState {
    address private first;
    address private second;
}
```

<details>
<summary><i>13 issue instances in 4 files:</i></summary>

```solidity
File: contracts/USDe.sol

16: address public minter;
```

| [Line #16](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L16) | 
```solidity
File: contracts/EthenaMinting.sol

63: IUSDe public usde;
81: mapping(uint256 => uint256) public mintedPerBlock;
83: mapping(uint256 => uint256) public redeemedPerBlock;
86: mapping(address => mapping(address => bool)) public delegatedSigner;
89: uint256 public maxMintPerBlock;
91: uint256 public maxRedeemPerBlock;
```

| [Line #63](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L63) | [Line #81](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L81) | [Line #83](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L83) | [Line #86](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L86) | [Line #89](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L89) | [Line #91](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L91) | 
```solidity
File: contracts/StakedUSDe.sol

42: uint256 public vestingAmount;
45: uint256 public lastDistributionTimestamp;
```

| [Line #42](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L42) | [Line #45](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L45) | 
```solidity
File: contracts/StakedUSDeV2.sol

18: mapping(address => UserCooldown) public cooldowns;
20: USDeSilo public silo;
22: uint24 public MAX_COOLDOWN_DURATION = 90 days;
24: uint24 public cooldownDuration;
```

| [Line #18](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L18) | [Line #20](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L20) | [Line #22](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L22) | [Line #24](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L24) | </details>


### [G-30] Optimize by Using Assembly for Low-Level Calls' Return Data

Even second return value from a low-level call is not assigned, it is still copied to memory, leading to additional gas costs.
By employing assembly, you can bypass this memory copying, achieving a 159 gas saving.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

250: (bool success,) = wallet.call{value: amount}("");
404: (bool success,) = (beneficiary).call{value: amount}("");
```

| [Line #250](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L250) | [Line #404](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L404) | </details>


### [G-31] Consider Using selfbalance() Over address(this).balance

The `selfbalance()` function from Yul can be more gas-efficient than using `address(this).balance` in certain scenarios.
Although the Solidity compiler is sometimes optimized enough to handle this, manually switching to `selfbalance()` could yield gas savings.

Note: Always thoroughly test both approaches to confirm the actual gas savings.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

403: if (address(this).balance < amount) revert InvalidAmount();
```

| [Line #403](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L403) | </details>


### [G-32] Missing Initial Value Check in Set Functions

A check regarding whether the current value and the new value are the same should be added.
This helps prevent unnecessary state changes and events in case the new value is the same as the current value.

<details>
<summary><i>12 issue instances in 4 files:</i></summary>

```solidity
File: contracts/USDe.sol

/// @audit Missing `newMinter` check before state change
25: minter = newMinter;
```

| [Line #25](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L25) | 
```solidity
File: contracts/EthenaMinting.sol

/// @audit Missing `_maxMintPerBlock` check before state change
220: _setMaxMintPerBlock(_maxMintPerBlock);
/// @audit Missing `_maxRedeemPerBlock` check before state change
225: _setMaxRedeemPerBlock(_maxRedeemPerBlock);
/// @audit Missing `asset` check before state change
261: emit AssetRemoved(asset);
/// @audit Missing `asset` check before state change
294: emit AssetAdded(asset);
/// @audit Missing `route` check before state change
368: totalRatio += route.ratios[i];
/// @audit Missing `amount` check before state change
427: totalTransferred += amountToTransfer;
/// @audit Missing `_maxMintPerBlock` check before state change
438: maxMintPerBlock = _maxMintPerBlock;
/// @audit Missing `_maxRedeemPerBlock` check before state change
445: maxRedeemPerBlock = _maxRedeemPerBlock;
```

| [Line #220](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L220) | [Line #225](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L225) | [Line #261](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L261) | [Line #294](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L294) | [Line #368](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L368) | [Line #427](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L427) | [Line #438](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L438) | [Line #445](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L445) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit Missing `duration` check before state change
132: cooldownDuration = duration;
```

| [Line #132](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L132) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

/// @audit Missing `newAdmin` check before state change
27: _pendingDefaultAdmin = newAdmin;
/// @audit Missing `account` check before state change
76: _currentDefaultAdmin = account;
```

| [Line #27](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L27) | [Line #76](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L76) | </details>


### [G-33] State Variables Should Be `immutable` Since They Are Only Set in the Constructor

State variables that are only set in the constructor and are not modified elsewhere in the code should be declared as `immutable`.
This can optimize gas usage as `immutable` variables are read from code, not from storage.

<details>
<summary><i>2 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

122: usde = _usde;
```

| [Line #122](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L122) | 
```solidity
File: contracts/StakedUSDeV2.sol

43: silo = new USDeSilo(address(this), address(_asset));
```

| [Line #43](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L43) | </details>


### [G-34] Avoid Using Small Size Integers

Usage of uints/ints smaller than 32 bytes (256 bits) incurs overhead. The Ethereum Virtual Machine (EVM) operates on 32 bytes at a time. Therefore, if an element is smaller than 32 bytes, the EVM must use more operations to reduce the size of the element from 32 bytes to the desired size. 

Operations involving smaller size uints/ints cost extra gas due to the compiler having to clear the higher bits of the memory word before operating on the small size integer. This also includes the associated stack operations of doing so. 

It's recommended to use larger sizes and downcast where needed to optimize for gas efficiency.

<details>
<summary><i>8 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

36: "Order(uint8 order_type,uint256 expiry,uint256 nonce,address benefactor,address beneficiary,address collateral_asset,uint256 collateral_amount,uint256 usde_amount)"
  );
```

| [Line #36](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L36) | 
```solidity
File: contracts/StakedUSDe.sol

184: function decimals() public pure override(ERC4626, ERC20) returns (uint8) {
```

| [Line #184](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L184) | 
```solidity
File: contracts/StakedUSDeV2.sol

22: uint24 public MAX_COOLDOWN_DURATION = 90 days;
24: uint24 public cooldownDuration;
100: cooldowns[owner].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
116: cooldowns[owner].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
126: function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
131: uint24 previousDuration = cooldownDuration;
```

| [Line #22](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L22) | [Line #24](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L24) | [Line #100](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L100) | [Line #116](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L116) | [Line #126](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L126) | [Line #131](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L131) | </details>


### [G-35] Optimize Gas by Splitting `if() revert` Statements

Using boolean operators in a single `if() revert` statement can consume more gas than necessary.
Consider splitting these statements to save gas.

<details>
<summary><i>8 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

248: if (wallet == address(0) || !_custodianAddresses.contains(wallet)) revert InvalidAddress();
291: if (asset == address(0) || asset == address(usde) || !_supportedAssets.add(asset)) {
      revert InvalidAssetAddress();
299: if (custodian == address(0) || custodian == address(usde) || !_custodianAddresses.add(custodian)) {
      revert InvalidCustodianAddress();
342: if (!(signer == order.benefactor || delegatedSigner[signer][order.benefactor])) revert InvalidSignature();
421: if (!_supportedAssets.contains(asset) || asset == NATIVE_TOKEN) revert UnsupportedAsset();
```

| [Line #248](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L248) | [Line #291](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L291) | [Line #299](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L299) | [Line #342](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L342) | [Line #421](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L421) | 
```solidity
File: contracts/StakedUSDe.sol

75: if (_owner == address(0) || _initialRewarder == address(0) || address(_asset) == address(0)) {
      revert InvalidZeroAddress();
210: if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
      revert OperationNotAllowed();
232: if (hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)) {
      revert OperationNotAllowed();
```

| [Line #75](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L75) | [Line #210](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L210) | [Line #232](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L232) | </details>


### [G-36] State variables should be cached (stack/memory/storage pointer) rather than re-reading them from storage

Caching state variables in local variables can optimize gas usage, as accessing the stack is cheaper than accessing storage.

The instances below point to the second+ access of a state variable within a function.

<details>
<summary><i>12 issue instances in 3 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit function _setMaxMintPerBlock() uses state variable `maxMintPerBlock` 2 times
437: uint256 oldMaxMintPerBlock = maxMintPerBlock;
439: emit MaxMintPerBlockChanged(oldMaxMintPerBlock, maxMintPerBlock);
/// @audit function _setMaxRedeemPerBlock() uses state variable `maxRedeemPerBlock` 2 times
444: uint256 oldMaxRedeemPerBlock = maxRedeemPerBlock;
446: emit MaxRedeemPerBlockChanged(oldMaxRedeemPerBlock, maxRedeemPerBlock);
```

| [Line #437](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L437) | [Line #439](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L439) | [Line #444](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L444) | [Line #446](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L446) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit function setCooldownDuration() uses state variable `cooldownDuration` 2 times
131: uint24 previousDuration = cooldownDuration;
133: emit CooldownDurationUpdated(previousDuration, cooldownDuration);
```

| [Line #131](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L131) | [Line #133](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L133) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

/// @audit function _grantRole() uses state variable `_currentDefaultAdmin` 2 times
74: emit AdminTransferred(_currentDefaultAdmin, account);
75: _revokeRole(DEFAULT_ADMIN_ROLE, _currentDefaultAdmin);
```

| [Line #74](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L74) | [Line #75](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L75) | </details>


### [G-37] Optimize Storage with Byte Truncation for Time Related State Variables

Certain state variables, particularly timestamps, can be safely stored using `uint32`. 
By optimizing these variables, contracts can utilize storage more efficiently.
This not only results in a reduction in the initial gas costs (due to fewer Gsset operations) but also provides savings in subsequent read and write operations.
Consider truncating the timestamp bytes for optimal storage use.

<details>
<summary><i>4 issue instances in 2 files:</i></summary>

```solidity
File: contracts/StakedUSDe.sol

/// @audit Time related state variable `VESTING_PERIOD` can be optimized by using uint32 instead of uint256
34: uint256 private constant VESTING_PERIOD = 8 hours;
/// @audit Time related state variable `lastDistributionTimestamp` can be optimized by using uint32 instead of uint256
45: uint256 public lastDistributionTimestamp;
```

| [Line #34](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L34) | [Line #45](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L45) | 
```solidity
File: contracts/StakedUSDeV2.sol

/// @audit Time related state variable `MAX_COOLDOWN_DURATION` can be optimized by using uint32 instead of uint24
22: uint24 public MAX_COOLDOWN_DURATION = 90 days;
/// @audit Time related state variable `cooldownDuration` can be optimized by using uint32 instead of uint24
24: uint24 public cooldownDuration;
```

| [Line #22](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L22) | [Line #24](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L24) | </details>


### [G-38] Avoid Zero Transfers to Save Gas

Performing token or Ether transfers with a zero amount may result in unnecessary gas consumption. 
The absence of a zero-amount check before a transfer or send operation can lead to wasted gas, as the state of the contract remains the same even if the amount is zero. 
Adding a conditional check for zero amounts can prevent these costly, unnecessary operations, thereby optimizing the contract's gas usage.

<details>
<summary><i>3 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit `amount` has not been checked for zero value before transfer
253: IERC20(asset).safeTransfer(wallet, amount);
/// @audit `amountToTransfer` has not been checked for zero value before transfer
426: token.safeTransferFrom(benefactor, addresses[i], amountToTransfer);
```

| [Line #253](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L253) | [Line #426](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L426) | 
```solidity
File: contracts/USDeSilo.sol

/// @audit `amount` has not been checked for zero value before transfer
29: USDE.transfer(to, amount);
```

| [Line #29](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L29) | </details>


### [G-39] Optimize Unsigned Integer Comparison With Zero

For unsigned integers, checking whether the integer is not equal to zero (`!= 0`) is less gas-intensive than checking whether it is greater than zero (`> 0`). 

This is because the Ethereum Virtual Machine (EVM) can perform a simple bitwise operation to check if any bit is set (which directly translates to `!= 0`), while checking for `> 0` requires additional logic.

As such, when dealing with unsigned integers in Solidity, it is recommended to use the `!= 0` comparison for gas optimization.

<details>
<summary><i>3 issue instances in 2 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

430: if (remainingBalance > 0) {
```

| [Line #430](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L430) | 
```solidity
File: contracts/StakedUSDe.sol

90: if (getUnvestedAmount() > 0) revert StillVesting();
193: if (_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();
```

| [Line #90](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L90) | [Line #193](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L193) | </details>


### [G-40] Optimize Increment and Decrement in loops with `unchecked` keyword

Use `unchecked{i++}` or `unchecked{++i}` instead of `i++` or `++i` when it is not possible for them to overflow.
This is applicable for Solidity version 0.8.0 or higher and saves 30-40 gas per loop.

<details>
<summary><i>4 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

126: for (uint256 i = 0; i < _assets.length; i++) {
130: for (uint256 j = 0; j < _custodians.length; j++) {
363: for (uint256 i = 0; i < route.addresses.length; ++i) {
424: for (uint256 i = 0; i < addresses.length; ++i) {
```

| [Line #126](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L126) | [Line #130](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L130) | [Line #363](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L363) | [Line #424](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L424) | </details>


### [G-41] Use `unchecked` for Math Operations if they already checked

Some subtraction operations in the contract have implicit checks that prevent underflow. 
To optimize gas, consider wrapping such operations in an `unchecked` block. 
Always review the logic thoroughly before making changes to ensure the safety of operations.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDe.sol

/// @audit - mathematical operation `VESTING_PERIOD - timeSinceLastDistribution` checked above in line:
/// 176: if (timeSinceLastDistribution >= VESTING_PERIOD) {
180: return ((VESTING_PERIOD - timeSinceLastDistribution) * vestingAmount) / VESTING_PERIOD;
```

| [Line #180](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L180) | </details>


### [G-42] Delete Unused Internal Functions to save gas on deployment

Unused `internal` functions in a contract can waste gas during deployment.
Even if they're potentially useful for out-of-scope contracts, they clutter the codebase and divert attention during audits.
Remove them to optimize gas and improve focus on active code.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDe.sol

/// @audit Internal `_deposit()` Function declared but never used
203: function _deposit(address caller, address receiver, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
  {
```

| [Line #203](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L203) | </details>


### [G-43] Delete Unused State Variables

State variables that aren't used in the contract not only clutter the codebase but also consume unnecessary gas during deployment.
Specifically, setting non-zero initial values for state variables costs significant gas.
By removing these unused state variables, you can save on both deployment gas and potential future storage gas costs.
This optimization not only reduces gas expenditures but also enhances code clarity and maintainability.
Always ensure a thorough review to confirm that these variables are indeed redundant before removal.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

/// @audit Unused state variable: EIP712_DOMAIN_TYPEHASH
49: bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(abi.encodePacked(EIP712_DOMAIN));
```

| [Line #49](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L49) | </details>


### [G-44] Optimize Gas by Using Only Named Returns

The Solidity compiler can generate more efficient bytecode when using named returns.
It's recommended to replace anonymous returns with named returns for potential gas savings.

Example:
```solidity
/// 985 gas cost
function add(uint256 x, uint256 y) public pure returns (uint256) {
    return x + y;
}
/// 941 gas cost
function addNamed(uint256 x, uint256 y) public pure returns (uint256 res) {
    res = x + y;
}
```

<details>
<summary><i>18 issue instances in 4 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

265: function isSupportedAsset(address asset) external view returns (bool) {
308: function getDomainSeparator() public view returns (bytes32) {
316: function hashOrder(Order calldata order) public view override returns (bytes32) {
319: function encodeOrder(Order calldata order) public pure returns (bytes memory) {
333: function encodeRoute(Route calldata route) public pure returns (bytes memory) {
339: function verifyOrder(Order calldata order, Signature calldata signature) public view override returns (bool, bytes32) {
351: function verifyRoute(Route calldata route, OrderType orderType) public view override returns (bool) {
377: function verifyNonce(address sender, uint256 nonce) public view override returns (bool, uint256, uint256, uint256) {
391: function _deduplicateOrder(address sender, uint256 nonce) private returns (bool) {
451: function _computeDomainSeparator() internal view returns (bytes32) {
```

| [Line #265](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L265) | [Line #308](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L308) | [Line #316](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L316) | [Line #319](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L319) | [Line #333](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L333) | [Line #339](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L339) | [Line #351](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L351) | [Line #377](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L377) | [Line #391](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L391) | [Line #451](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L451) | 
```solidity
File: contracts/StakedUSDe.sol

166: function totalAssets() public view override returns (uint256) {
173: function getUnvestedAmount() public view returns (uint256) {
184: function decimals() public pure override(ERC4626, ERC20) returns (uint8) {
```

| [Line #166](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L166) | [Line #173](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L173) | [Line #184](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDe.sol#L184) | 
```solidity
File: contracts/StakedUSDeV2.sol

52: function withdraw(uint256 assets, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
65: function redeem(uint256 shares, address receiver, address owner)
    public
    virtual
    override
    ensureCooldownOff
    returns (uint256)
  {
95: function cooldownAssets(uint256 assets, address owner) external ensureCooldownOn returns (uint256) {
111: function cooldownShares(uint256 shares, address owner) external ensureCooldownOn returns (uint256) {
```

| [Line #52](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L52) | [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L65) | [Line #95](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L95) | [Line #111](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L111) | 
```solidity
File: contracts/SingleAdminAccessControl.sol

65: function owner() public view virtual returns (address) {
```

| [Line #65](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/SingleAdminAccessControl.sol#L65) | </details>


## Disputed Findings Details

### [D-01] Casting `block.timestamp` to Smaller Integer Types Limit Contract Lifespan

Using `uint40` or higher is safe for contracts since a lifespan will be exceed in year 11421 or more.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/StakedUSDeV2.sol

100: cooldowns[owner].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
116: cooldowns[owner].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
```

| [Line #100](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L100) | [Line #116](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/StakedUSDeV2.sol#L116) | </details>


### [D-02] Explicit Visibility Recommended in Variable/Function Definitions

Visibility is explisitly defined, variable declaration is split to multiple lines.

<details>
<summary><i>2 issue instances in 1 files:</i></summary>

```solidity
File: contracts/EthenaMinting.sol

28: bytes32 private constant EIP712_DOMAIN =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
35: bytes32 private constant ORDER_TYPE = keccak256(
    "Order(uint8 order_type,uint256 expiry,uint256 nonce,address benefactor,address beneficiary,address collateral_asset,uint256 collateral_amount,uint256 usde_amount)"
  );
```

| [Line #28](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L28) | [Line #35](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L35) | </details>



### [D-03] Centralized Control Risk in Privileged Functions

Trusted Roles based on readme

<details>
<summary><i>3 issue instances in 2 files:</i></summary>

```solidity
File: contracts/USDe.sol

/// @audit `onlyOwner` modifier is used to restrict access
22: function setMinter(address newMinter) external onlyOwner {
/// @audit `onlyOwner` modifier is used to restrict access
32: function renounceOwnership() public view override onlyOwner {
```

| [Line #22](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L22) | [Line #32](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L32) | 
```solidity
File: contracts/USDeSilo.sol

/// @audit `onlyStakingVault` modifier is used to restrict access
27: function withdraw(address to, uint256 amount) external onlyStakingVault {
```

| [Line #27](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L27) | </details>


### [D-04] Unchecked Return Values of `transfer()/transferFrom()`

Theit own USDe stablecoin is used, so it is trusted.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/USDeSilo.sol

29: USDE.transfer(to, amount);
```

| [Line #29](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L29) | </details>

### [D-05] Unsafe use of `transfer()/transferFrom()` with IERC20

Theit own USDe stablecoin is used, so it is trusted.

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/USDeSilo.sol

29: USDE.transfer(to, amount);
```

| [Line #29](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDeSilo.sol#L29) | </details>

### [D-06] Mint to zero address

USDe is OpenZeppelin ERC20, it revert on mint to zero address.

<details>
<summary><i>2 issue instances in 2 files:</i></summary>

```solidity
File: contracts/USDe.sol

27: function mint(address to, uint256 amount) external {
```

| [Line #27](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L27) | 
```solidity
File: contracts/EthenaMinting.sol

162: function mint(Order calldata order, Route calldata route, Signature calldata signature)
    external
    override
    nonReentrant
    onlyRole(MINTER_ROLE)
    belowMaxMintPerBlock(order.usde_amount)
  {
```

| [Line #162](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/EthenaMinting.sol#L162) | </details>


### [D-07] Owner can renounce Ownership

function renounceOwnership() public view override onlyOwner {
  revert CantRenounceOwnership();
}

<details>
<summary><i>1 issue instances in 1 files:</i></summary>

```solidity
File: contracts/USDe.sol

7: import "@openzeppelin/contracts/access/Ownable2Step.sol";
```

| [Line #7](https://github.com/code-423n4/2023-10-ethena/blob/main/contracts/USDe.sol#L7) | </details>
