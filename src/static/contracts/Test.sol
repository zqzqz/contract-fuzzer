pragma solidity ^0.4.24;

contract Test {
    address public owner;
    mapping(address => uint) public payments;

    constructor() public {
        owner = msg.sender;
    }

    function test1(uint a) public {
        owner = msg.sender;
        payments[msg.sender] += a;
    }

    function test2() public {
        require(owner == msg.sender);
        msg.sender.transfer(payments[msg.sender]);
    }
}