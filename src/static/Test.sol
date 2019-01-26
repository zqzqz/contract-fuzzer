pragma solidity ^0.4.24;

contract Test {
    address owner;
    constructor() public {
        owner = msg.sender;
    }

    function test(uint a) public returns (uint) {
        owner = msg.sender;
        return a + 1;
    }
}