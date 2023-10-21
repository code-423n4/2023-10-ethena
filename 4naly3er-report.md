# Report


## Gas Optimizations


| |Issue|Instances|
|-|:-|:-:|
| [GAS-1](#GAS-1) | Using bools for storage incurs overhead | 1 |
| [GAS-2](#GAS-2) | Cache array length outside of loop | 4 |
| [GAS-3](#GAS-3) | For Operations that will not overflow, you could use unchecked | 115 |
| [GAS-4](#GAS-4) | Don't initialize variables with default value | 6 |
| [GAS-5](#GAS-5) | Functions guaranteed to revert when called by normal users can be marked `payable` | 20 |
| [GAS-6](#GAS-6) | `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too) | 2 |
| [GAS-7](#GAS-7) | Use != 0 instead of > 0 for unsigned integer comparison | 3 |
### <a name="GAS-1"></a>[GAS-1] Using bools for storage incurs overhead
Use uint256(1) and uint256(2) for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from ‘false’ to ‘true’, after having been ‘true’ in the past. See [source](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27).

*Instances (1)*:
```solidity
File: contracts/EthenaMinting.sol

86:   mapping(address => mapping(address => bool)) public delegatedSigner;

```

### <a name="GAS-2"></a>[GAS-2] Cache array length outside of loop
If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

*Instances (4)*:
```solidity
File: contracts/EthenaMinting.sol

126:     for (uint256 i = 0; i < _assets.length; i++) {

130:     for (uint256 j = 0; j < _custodians.length; j++) {

363:     for (uint256 i = 0; i < route.addresses.length; ++i) {

424:     for (uint256 i = 0; i < addresses.length; ++i) {

```

### <a name="GAS-3"></a>[GAS-3] For Operations that will not overflow, you could use unchecked

*Instances (115)*:
```solidity
File: contracts/EthenaMinting.sol

8: import "./SingleAdminAccessControl.sol";

9: import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

9: import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

9: import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

10: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

10: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

10: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

10: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

10: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

11: import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

11: import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

11: import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

11: import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

12: import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

12: import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

12: import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

12: import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

14: import "./interfaces/IUSDe.sol";

14: import "./interfaces/IUSDe.sol";

15: import "./interfaces/IEthenaMinting.sol";

15: import "./interfaces/IEthenaMinting.sol";

98:     if (mintedPerBlock[block.number] + mintAmount > maxMintPerBlock) revert MaxMintPerBlockExceeded();

105:     if (redeemedPerBlock[block.number] + redeemAmount > maxRedeemPerBlock) revert MaxRedeemPerBlockExceeded();

126:     for (uint256 i = 0; i < _assets.length; i++) {

126:     for (uint256 i = 0; i < _assets.length; i++) {

130:     for (uint256 j = 0; j < _custodians.length; j++) {

130:     for (uint256 j = 0; j < _custodians.length; j++) {

174:     mintedPerBlock[block.number] += order.usde_amount;

205:     redeemedPerBlock[block.number] += order.usde_amount;

363:     for (uint256 i = 0; i < route.addresses.length; ++i) {

363:     for (uint256 i = 0; i < route.addresses.length; ++i) {

368:       totalRatio += route.ratios[i];

424:     for (uint256 i = 0; i < addresses.length; ++i) {

424:     for (uint256 i = 0; i < addresses.length; ++i) {

425:       uint256 amountToTransfer = (amount * ratios[i]) / 10_000;

425:       uint256 amountToTransfer = (amount * ratios[i]) / 10_000;

427:       totalTransferred += amountToTransfer;

429:     uint256 remainingBalance = amount - totalTransferred;

431:       token.safeTransferFrom(benefactor, addresses[addresses.length - 1], remainingBalance);

```

```solidity
File: contracts/SingleAdminAccessControl.sol

4: import "@openzeppelin/contracts/access/AccessControl.sol";

4: import "@openzeppelin/contracts/access/AccessControl.sol";

4: import "@openzeppelin/contracts/access/AccessControl.sol";

5: import "@openzeppelin/contracts/interfaces/IERC5313.sol";

5: import "@openzeppelin/contracts/interfaces/IERC5313.sol";

5: import "@openzeppelin/contracts/interfaces/IERC5313.sol";

6: import "./interfaces/ISingleAdminAccessControl.sol";

6: import "./interfaces/ISingleAdminAccessControl.sol";

```

```solidity
File: contracts/StakedUSDe.sol

8: import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

8: import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

8: import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

8: import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

8: import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

9: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

9: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

9: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

9: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

9: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

10: import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

10: import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

10: import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

11: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

11: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

11: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

11: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

11: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

11: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

12: import "./SingleAdminAccessControl.sol";

13: import "./interfaces/IStakedUSDe.sol";

13: import "./interfaces/IStakedUSDe.sol";

91:     uint256 newVestingAmount = amount + getUnvestedAmount();

167:     return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();

174:     uint256 timeSinceLastDistribution = block.timestamp - lastDistributionTimestamp;

180:     return ((VESTING_PERIOD - timeSinceLastDistribution) * vestingAmount) / VESTING_PERIOD;

180:     return ((VESTING_PERIOD - timeSinceLastDistribution) * vestingAmount) / VESTING_PERIOD;

180:     return ((VESTING_PERIOD - timeSinceLastDistribution) * vestingAmount) / VESTING_PERIOD;

```

```solidity
File: contracts/StakedUSDeV2.sol

4: import "./StakedUSDe.sol";

5: import "./interfaces/IStakedUSDeCooldown.sol";

5: import "./interfaces/IStakedUSDeCooldown.sol";

6: import "./USDeSilo.sol";

100:     cooldowns[owner].cooldownEnd = uint104(block.timestamp) + cooldownDuration;

101:     cooldowns[owner].underlyingAmount += assets;

116:     cooldowns[owner].cooldownEnd = uint104(block.timestamp) + cooldownDuration;

117:     cooldowns[owner].underlyingAmount += assets;

```

```solidity
File: contracts/USDe.sol

4: import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

4: import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

4: import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

4: import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

5: import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

5: import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

5: import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

5: import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

5: import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

6: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

6: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

6: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

6: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

6: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

6: import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

7: import "@openzeppelin/contracts/access/Ownable2Step.sol";

7: import "@openzeppelin/contracts/access/Ownable2Step.sol";

7: import "@openzeppelin/contracts/access/Ownable2Step.sol";

8: import "./interfaces/IUSDeDefinitions.sol";

8: import "./interfaces/IUSDeDefinitions.sol";

```

```solidity
File: contracts/USDeSilo.sol

4: import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

4: import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

4: import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

4: import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

5: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

5: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

5: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

5: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

5: import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

6: import "../contracts/interfaces/IUSDeSiloDefinitions.sol";

6: import "../contracts/interfaces/IUSDeSiloDefinitions.sol";

6: import "../contracts/interfaces/IUSDeSiloDefinitions.sol";

```

### <a name="GAS-4"></a>[GAS-4] Don't initialize variables with default value

*Instances (6)*:
```solidity
File: contracts/EthenaMinting.sol

126:     for (uint256 i = 0; i < _assets.length; i++) {

130:     for (uint256 j = 0; j < _custodians.length; j++) {

356:     uint256 totalRatio = 0;

363:     for (uint256 i = 0; i < route.addresses.length; ++i) {

423:     uint256 totalTransferred = 0;

424:     for (uint256 i = 0; i < addresses.length; ++i) {

```

### <a name="GAS-5"></a>[GAS-5] Functions guaranteed to revert when called by normal users can be marked `payable`
If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.

*Instances (20)*:
```solidity
File: contracts/EthenaMinting.sol

219:   function setMaxMintPerBlock(uint256 _maxMintPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {

224:   function setMaxRedeemPerBlock(uint256 _maxRedeemPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {

229:   function disableMintRedeem() external onlyRole(GATEKEEPER_ROLE) {

247:   function transferToCustody(address wallet, address asset, uint256 amount) external nonReentrant onlyRole(MINTER_ROLE) {

259:   function removeSupportedAsset(address asset) external onlyRole(DEFAULT_ADMIN_ROLE) {

270:   function removeCustodianAddress(address custodian) external onlyRole(DEFAULT_ADMIN_ROLE) {

277:   function removeMinterRole(address minter) external onlyRole(GATEKEEPER_ROLE) {

283:   function removeRedeemerRole(address redeemer) external onlyRole(GATEKEEPER_ROLE) {

290:   function addSupportedAsset(address asset) public onlyRole(DEFAULT_ADMIN_ROLE) {

298:   function addCustodianAddress(address custodian) public onlyRole(DEFAULT_ADMIN_ROLE) {

```

```solidity
File: contracts/SingleAdminAccessControl.sol

25:   function transferAdmin(address newAdmin) external onlyRole(DEFAULT_ADMIN_ROLE) {

41:   function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {

50:   function revokeRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {

```

```solidity
File: contracts/StakedUSDe.sol

89:   function transferInRewards(uint256 amount) external nonReentrant onlyRole(REWARDER_ROLE) notZero(amount) {

138:   function rescueTokens(address token, uint256 amount, address to) external onlyRole(DEFAULT_ADMIN_ROLE) {

148:   function redistributeLockedAmount(address from, address to) external onlyRole(DEFAULT_ADMIN_ROLE) {

```

```solidity
File: contracts/StakedUSDeV2.sol

126:   function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {

```

```solidity
File: contracts/USDe.sol

23:   function setMinter(address newMinter) external onlyOwner {

33:   function renounceOwnership() public view override onlyOwner {

```

```solidity
File: contracts/USDeSilo.sol

28:   function withdraw(address to, uint256 amount) external onlyStakingVault {

```

### <a name="GAS-6"></a>[GAS-6] `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too)
*Saves 5 gas per loop*

*Instances (2)*:
```solidity
File: contracts/EthenaMinting.sol

126:     for (uint256 i = 0; i < _assets.length; i++) {

130:     for (uint256 j = 0; j < _custodians.length; j++) {

```

### <a name="GAS-7"></a>[GAS-7] Use != 0 instead of > 0 for unsigned integer comparison

*Instances (3)*:
```solidity
File: contracts/EthenaMinting.sol

430:     if (remainingBalance > 0) {

```

```solidity
File: contracts/StakedUSDe.sol

90:     if (getUnvestedAmount() > 0) revert StillVesting();

193:     if (_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();

```


## Low Issues


| |Issue|Instances|
|-|:-|:-:|
| [L-1](#L-1) |  `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()` | 1 |
| [L-2](#L-2) | Unsafe ERC20 operation(s) | 1 |
### <a name="L-1"></a>[L-1]  `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()`
Use `abi.encode()` instead which will pad items to 32 bytes, which will [prevent hash collisions](https://docs.soliditylang.org/en/v0.8.13/abi-spec.html#non-standard-packed-mode) (e.g. `abi.encodePacked(0x123,0x456)` => `0x123456` => `abi.encodePacked(0x1,0x23456)`, but `abi.encode(0x123,0x456)` => `0x0...1230...456`). "Unless there is a compelling reason, `abi.encode` should be preferred". If there is only one argument to `abi.encodePacked()` it can often be cast to `bytes()` or `bytes32()` [instead](https://ethereum.stackexchange.com/questions/30912/how-to-compare-strings-in-solidity#answer-82739).
If all arguments are strings and or bytes, `bytes.concat()` should be used instead

*Instances (1)*:
```solidity
File: contracts/EthenaMinting.sol

49:   bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(abi.encodePacked(EIP712_DOMAIN));

```

### <a name="L-2"></a>[L-2] Unsafe ERC20 operation(s)

*Instances (1)*:
```solidity
File: contracts/USDeSilo.sol

29:     USDE.transfer(to, amount);

```


## Medium Issues


| |Issue|Instances|
|-|:-|:-:|
| [M-1](#M-1) | Centralization Risk for trusted owners | 29 |
### <a name="M-1"></a>[M-1] Centralization Risk for trusted owners

#### Impact:
Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

*Instances (29)*:
```solidity
File: contracts/EthenaMinting.sol

21: contract EthenaMinting is IEthenaMinting, SingleAdminAccessControl, ReentrancyGuard {

166:     onlyRole(MINTER_ROLE)

198:     onlyRole(REDEEMER_ROLE)

219:   function setMaxMintPerBlock(uint256 _maxMintPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {

224:   function setMaxRedeemPerBlock(uint256 _maxRedeemPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {

229:   function disableMintRedeem() external onlyRole(GATEKEEPER_ROLE) {

247:   function transferToCustody(address wallet, address asset, uint256 amount) external nonReentrant onlyRole(MINTER_ROLE) {

259:   function removeSupportedAsset(address asset) external onlyRole(DEFAULT_ADMIN_ROLE) {

270:   function removeCustodianAddress(address custodian) external onlyRole(DEFAULT_ADMIN_ROLE) {

277:   function removeMinterRole(address minter) external onlyRole(GATEKEEPER_ROLE) {

283:   function removeRedeemerRole(address redeemer) external onlyRole(GATEKEEPER_ROLE) {

290:   function addSupportedAsset(address asset) public onlyRole(DEFAULT_ADMIN_ROLE) {

298:   function addCustodianAddress(address custodian) public onlyRole(DEFAULT_ADMIN_ROLE) {

```

```solidity
File: contracts/SingleAdminAccessControl.sol

13: abstract contract SingleAdminAccessControl is IERC5313, ISingleAdminAccessControl, AccessControl {

13: abstract contract SingleAdminAccessControl is IERC5313, ISingleAdminAccessControl, AccessControl {

13: abstract contract SingleAdminAccessControl is IERC5313, ISingleAdminAccessControl, AccessControl {

25:   function transferAdmin(address newAdmin) external onlyRole(DEFAULT_ADMIN_ROLE) {

41:   function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {

50:   function revokeRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {

```

```solidity
File: contracts/StakedUSDe.sol

21: contract StakedUSDe is SingleAdminAccessControl, ReentrancyGuard, ERC20Permit, ERC4626, IStakedUSDe {

89:   function transferInRewards(uint256 amount) external nonReentrant onlyRole(REWARDER_ROLE) notZero(amount) {

108:     onlyRole(BLACKLIST_MANAGER_ROLE)

122:     onlyRole(BLACKLIST_MANAGER_ROLE)

138:   function rescueTokens(address token, uint256 amount, address to) external onlyRole(DEFAULT_ADMIN_ROLE) {

148:   function redistributeLockedAmount(address from, address to) external onlyRole(DEFAULT_ADMIN_ROLE) {

```

```solidity
File: contracts/StakedUSDeV2.sol

126:   function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {

```

```solidity
File: contracts/USDe.sol

15: contract USDe is Ownable2Step, ERC20Burnable, ERC20Permit, IUSDeDefinitions {

23:   function setMinter(address newMinter) external onlyOwner {

33:   function renounceOwnership() public view override onlyOwner {

```

