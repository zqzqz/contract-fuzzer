pragma solidity ^0.4.24;

contract Test {
    address owner;
    mapping(address => uint) payments;

    function test1(uint a) public payable {
        require(a <= 1 ether);
        payments[msg.sender] += a;
        msg.sender.transfer(this.balance);
    }

    function test2() public {
        require(owner == msg.sender);
        msg.sender.transfer(payments[msg.sender]);
    }
}