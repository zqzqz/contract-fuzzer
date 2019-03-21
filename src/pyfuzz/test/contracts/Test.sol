pragma solidity ^0.4.24;

contract Test {
    address owner;
    mapping(address => uint) payments;

    function test1(uint a) public {
        owner = msg.sender;
        payments[msg.sender] += a;
    }

    function test2() public {
        require(owner == msg.sender);
        msg.sender.transfer(payments[msg.sender]);
    }

    function TimestampDependency() public {
        uint value = block.timestamp % 1000;
        msg.sender.transfer(value);
    }

    // function () payable public {

    // }
}