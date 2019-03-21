pragma solidity ^0.4.24;

contract Test {
    function BlockNumberDependency() public {
        uint value = block.number + 1000000000000000000;
        msg.sender.transfer(value);
    }
}