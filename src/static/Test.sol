pragma solidity ^0.4.24;

contract Test {
    address owner;
    constructor() public {
        owner = msg.sender;
    }

    function test() public {
        owner = msg.sender;
    }
}