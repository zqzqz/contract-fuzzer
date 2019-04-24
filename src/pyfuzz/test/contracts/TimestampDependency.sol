pragma solidity ^0.4.24;

contract Test {
    function TimestampDependency() public {
        uint value = block.timestamp % 1000000;
        msg.sender.transfer(value);
    }
}