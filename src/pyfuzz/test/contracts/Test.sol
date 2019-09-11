pragma solidity ^0.4.24;

contract Test {
    address owner;
    mapping(address => uint) payments;
    event TestEvent(uint num);

    function test1(uint a) public payable {
        emit TestEvent(a);
        payments[msg.sender] += a;
        owner = msg.sender;
    }

    function test2() public {
        require(owner == msg.sender);
        msg.sender.transfer(payments[msg.sender]);
    }
}