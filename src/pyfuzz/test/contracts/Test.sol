pragma solidity ^0.4.24;

contract Test {
    address owner;
    mapping(address => uint) payments;

    function test1(uint a, uint b) public payable {
        require(a <= 1 ether);
        if (b > 10) {
            payments[msg.sender] += a;
        } else {
            payments[msg.sender] += b;
        }
        address tmp = msg.sender;
        owner = tmp;
    }

    function test2() public {
        require(owner == msg.sender);
        msg.sender.transfer(payments[msg.sender]);
    }
}